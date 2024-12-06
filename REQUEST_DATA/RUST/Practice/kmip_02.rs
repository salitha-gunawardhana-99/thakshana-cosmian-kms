use std::{fs, sync::Arc}; // Allows sharing KMSServer across threads safely.

use actix_web::{
    post,
    web::{Data, Json},
    HttpRequest,
};
use cosmian_kmip::kmip::{
    kmip_messages::Message,
    ttlv::{deserializer::from_ttlv, serializer::to_ttlv, TTLV},
};
use serde_json::to_string;
use tracing::info;

use crate::{
    core::{extra_database_params::ExtraDatabaseParams, operations::dispatch, KMS},
    database::KMSServer,
    result::KResult,
};

fn print_type_of<T>(_: &T) {
    println!("{}", std::any::type_name::<T>());
}

/// Generate KMIP JSON TTLV and send it to the KMIP server
#[post("/kmip/2_1")]
pub(crate) async fn kmip(
    req_http: HttpRequest,
    body: String,
    kms: Data<Arc<KMSServer>>,
) -> KResult<Json<TTLV>> {
    let span = tracing::span!(tracing::Level::INFO, "kmip_2_1");
    let _enter = span.enter();

    /*Note: convert json string into ttlv object */
    println!("body: {}", body);
    print_type_of(&body);
    let ttlv = serde_json::from_str::<TTLV>(&body)?;
    // println!("body: {}", Json(ttlv));
    print_type_of(&ttlv);

    let database_params = kms.get_sqlite_enc_secrets(&req_http)?;
    let user = kms.get_user(&req_http);

    /*Note: logging statement in Rust that uses the log crate (or a similar logging framework) to log information about a KMIP request. */
    info!(target: "kmip", user=user, tag=ttlv.tag.as_str(), "POST /kmip. Request: {:?} {}", ttlv.tag.as_str(), user);

    let ttlv_out: TTLV;

    if ttlv.tag.as_str() == "GenerateEnrolData" {
        ttlv_out = handle_ttlv_enrol(&kms, &body, &ttlv, &user, database_params.as_ref()).await?;
    } else {
        /*Note: All the operations happens here and receive the response */
        ttlv_out = handle_ttlv(&kms, &ttlv, &user, database_params.as_ref()).await?;
        // print_type_of(&ttlv);
    }

    // Serialize TTLV back to JSON for printing
    let serialized_ttlv = to_string(&ttlv_out)?;

    // Print the serialized TTLV JSON to the console or log
    println!("Serialized TTLV: {}", serialized_ttlv);

    /*Note: Ok(Json(ttlv)) in the context of this code is returning a successful HTTP response, where the body of the response contains the ttlv data serialized into JSON format. */
    // print_type_of(&Json(ttlv));
    // let json_out = fs::read_to_string("crate/server/src/routes/enrol_data/Response.json")?;
    Ok(Json(ttlv_out))
    // let ttlv_fin = serde_json::from_str::<TTLV>(&json_out)?;
    // Ok(Json(ttlv_fin))
}

/// Handle input TTLV requests
///
/// Process the TTLV-serialized input request and returns
/// the TTLV-serialized response.
///
/// The input request could be either a single KMIP `Operation` or
/// multiple KMIP `Operation`s serialized in a single KMIP `Message`
async fn handle_ttlv(
    kms: &KMS,
    ttlv: &TTLV,
    user: &str,
    database_params: Option<&ExtraDatabaseParams>,
) -> KResult<TTLV> {
    if ttlv.tag.as_str() == "Message" {
        let req = from_ttlv::<Message>(ttlv)?;
        let resp = kms.message(req, user, database_params).await?;
        Ok(to_ttlv(&resp)?)
    } else {
        let operation = dispatch(kms, ttlv, user, database_params).await?;
        Ok(to_ttlv(&operation)?)
    }
}

/*======================================================================================================== */

use std::error::Error;

use serde::Deserialize;

#[derive(Deserialize)]
struct DeviceInfo {
    #[serde(rename = "type")]
    _type: String,
    value: Vec<DeviceAttribute>,
}

#[derive(Deserialize)]
struct DeviceAttribute {
    tag: String,
    #[serde(rename = "type")]
    _type: String,
    value: String,
}

fn extract_device_info(json_body: &str) -> Result<(String, String), Box<dyn Error>> {
    // Parse the JSON string into DeviceInfo
    let device_info: DeviceInfo = serde_json::from_str(json_body)?;

    // Find the attributes and extract values
    let mut serial_number = String::new();
    let mut part_number = String::new();

    for attribute in device_info.value {
        match attribute.tag.as_str() {
            "SerialNumber" => serial_number = attribute.value,
            "PartNumber" => part_number = attribute.value,
            _ => (),
        }
    }

    // Return the extracted values
    if !serial_number.is_empty() && !part_number.is_empty() {
        Ok((serial_number, part_number))
    } else {
        Err("SerialNumber or PartNumber not found".into())
    }
}

/*======================================================================================================== */

use serde_json::Value;

pub fn update_json(
    json_str: &str,
    new_unique_identifier: &str,
    new_attribute_value: &str,
) -> Result<String, Box<dyn std::error::Error>> {
    // Parse the input JSON string into a serde_json::Value
    let mut root: Value = serde_json::from_str(json_str)?;

    // Navigate and update the UniqueIdentifier
    if let Some(attributes) = root
        .get_mut("value")
        .and_then(|v| v.as_array_mut())
        .and_then(|arr| arr.iter_mut().find(|item| item["tag"] == "Attributes"))
    {
        if let Some(attribute_values) = attributes.get_mut("value").and_then(|v| v.as_array_mut()) {
            for attr in attribute_values.iter_mut() {
                match attr["tag"].as_str() {
                    Some("UniqueIdentifier") => {
                        if let Some(value) = attr.get_mut("value") {
                            *value = Value::String(new_unique_identifier.to_string());
                        }
                    }
                    Some("VendorAttributes") => {
                        if let Some(vendor_attributes) =
                            attr.get_mut("value").and_then(|v| v.as_array_mut())
                        {
                            for vendor_attr in vendor_attributes.iter_mut() {
                                if let Some(vendor_inner) =
                                    vendor_attr.get_mut("value").and_then(|v| v.as_array_mut())
                                {
                                    for inner_attr in vendor_inner.iter_mut() {
                                        if inner_attr["tag"] == "AttributeValue" {
                                            if let Some(value) = inner_attr.get_mut("value") {
                                                *value =
                                                    Value::String(new_attribute_value.to_string());
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                    _ => {}
                }
            }
        }
    }

    // Serialize the updated JSON back to a string
    Ok(serde_json::to_string_pretty(&root)?)
}

/*======================================================================================================== */

#[derive(Deserialize)]
struct ImportResponse {
    #[allow(unused)]
    tag: String,
    #[allow(unused)]
    #[serde(rename = "type")]
    data_type: String,
    value: Vec<Attribute>,
}

#[derive(Deserialize)]
struct Attribute {
    #[allow(unused)]
    tag: String,
    #[allow(unused)]
    #[serde(rename = "type")]
    data_type: String,
    value: String,
}

fn extract_unique_identifier(json_body: &str) -> KResult<String> {
    // Parse the JSON string into the `ImportResponse` struct
    let response: ImportResponse = serde_json::from_str(json_body)?;

    let mut unique_id = String::new();

    // Find the attribute with the tag "UniqueIdentifier"
    if let Some(attribute) = response
        .value
        .iter()
        .find(|attr| attr.tag == "UniqueIdentifier")
    {
        unique_id = attribute.value.clone().to_string();
    }
    Ok(unique_id)
}

pub async fn import_ca(
    kms: &KMS,
    user: &str,
    database_params: Option<&ExtraDatabaseParams>,
) -> KResult<String> {
    // Read the JSON file containing the CA import request
    let import_ca_req = fs::read_to_string("crate/server/src/routes/enrol_data/CA_import.json")?;

    // Deserialize the JSON into a TTLV operation
    let ttlv_operation = serde_json::from_str::<TTLV>(&import_ca_req)?;

    // Read the existing JSON file
    let file_path = "crate/server/src/routes/enrol_data/uid.json";
    let mut json_data: serde_json::Value = serde_json::from_str(&fs::read_to_string(file_path)?)?;

    // Check if "device_key_id" exists and is not empty
    if let Some(ca_private_key_id) = json_data.get("CA_PRIVATE_KEY_ID") {
        if ca_private_key_id.is_string() && !ca_private_key_id.as_str().unwrap_or("").is_empty() {
            // If it exists, use the value
            let unique_id = ca_private_key_id.as_str().unwrap_or("").to_string();
            println!("CA UIDddddddddddddddd");
            println!("CA UID: {}", unique_id);
            return Ok(unique_id);
        }
    }

    // If no valid "device_key_id" found, dispatch operation
    let operation = dispatch(kms, &ttlv_operation, user, database_params).await?;

    // Convert the operation result back to a TTLV string
    let rep_ttlv = to_ttlv(&operation)?;
    let resp = to_string(&rep_ttlv)?;

    // Extract the Unique Identifier
    let unique_id = extract_unique_identifier(&resp)?;

    // Update the "device_key_id" field in JSON data
    json_data["CA_PRIVATE_KEY_ID"] = serde_json::Value::String(unique_id.clone());

    // Write the updated JSON back to the file
    fs::write(file_path, serde_json::to_string_pretty(&json_data)?)?;

    // Print the final Unique Identifier
    println!("CA UID: {}", unique_id);

    // Return the unique ID
    Ok(unique_id)
}

/*======================================================================================================== */

use serde_json::json;

fn operation_status_json(tag: &str, type_str: &str, value: &str) -> Value {
    // Create the JSON structure with the provided inputs
    json!({
        "tag": tag,
        "type": type_str,
        "value": value
    })
}

use std::io;

fn append_to_response_json(file_path: &str, new_data: Value) -> io::Result<()> {
    // Read the existing JSON data from the file
    let mut existing_data: Value = serde_json::from_str(&fs::read_to_string(file_path)?)?;

    // Ensure the "value" field is an array (which it is in the original structure)
    if let Some(value_array) = existing_data
        .get_mut("value")
        .and_then(|v| v.as_array_mut())
    {
        // Append the new data to the array
        value_array.push(new_data);
    } else {
        return Err(io::Error::new(
            io::ErrorKind::Other,
            "Invalid structure in the existing JSON",
        ));
    }

    // Write the updated JSON back to the file
    fs::write(file_path, serde_json::to_string_pretty(&existing_data)?)?;
    Ok(())
}

async fn handle_create(
    kms: &KMS,
    user: &str,
    database_params: Option<&ExtraDatabaseParams>,
) -> KResult<Value> {
    // Read the existing JSON file
    let file_path = "crate/server/src/routes/enrol_data/uid.json";
    let mut json_data: serde_json::Value = serde_json::from_str(&fs::read_to_string(file_path)?)?;

    let create_req = fs::read_to_string("crate/server/src/routes/enrol_data/Create.json")?;
    let ttlv_operation = serde_json::from_str::<TTLV>(&create_req)?;
    let operation = dispatch(kms, &ttlv_operation, user, database_params).await?;

    // Convert the operation result back to a TTLV string
    let rep_ttlv = to_ttlv(&operation)?;
    let resp = to_string(&rep_ttlv)?;

    // Extract the Unique Identifier
    let unique_id = extract_unique_identifier(&resp)?;

    // Update the "device_key_id" field in JSON data
    json_data["DEVICE_KEY_ID"] = serde_json::Value::String(unique_id.clone());

    // Write the updated JSON back to the file
    fs::write(file_path, serde_json::to_string_pretty(&json_data)?)?;

    // Print the final Unique Identifier
    println!("DEVICE_KEY_ID: {}", unique_id);

    let operation_result = operation_status_json("Status", "TextString", "Success");

    // Return the unique ID
    Ok(operation_result)
}

/*======================================================================================================== */


/*======================================================================================================== */

async fn handle_ttlv_enrol(
    kms: &KMS,
    body: &String,
    _ttlv: &TTLV,
    user: &str,
    database_params: Option<&ExtraDatabaseParams>,
) -> KResult<TTLV> {
    // Extract SerialNumber and PartNumber
    let mut serial_num = String::new();
    let mut part_num = String::new();

    match extract_device_info(body) {
        Ok((serial_number, part_number)) => {
            serial_num = serial_number;
            part_num = part_number;
        }
        Err(e) => println!("Error: {}", e),
    }
    // Now the values are used, avoid the compiler warning about unused assignments
    println!("Serial Number: {}", serial_num);
    println!("Part Number: {}", part_num);

    let ca_uid = import_ca(kms, user, database_params).await?;
    println!("CA UID: {}", ca_uid);

    let new_appended = handle_create(kms, &user, database_params).await?;

    // Append new data to the existing JSON file
    let _unused = append_to_response_json(
        "crate/server/src/routes/enrol_data/GenerateEnrolDataResponse.json",
        new_appended,
    );

    let fin_res =
        fs::read_to_string("crate/server/src/routes/enrol_data/GenerateEnrolDataResponse.json")?;
    let fin_ttlv = serde_json::from_str::<TTLV>(&fin_res)?;

    Ok(fin_ttlv)
}

/*======================================================================================================== */
