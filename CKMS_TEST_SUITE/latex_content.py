# Define the LaTeX document content as a multi-line string
latex_begining = r"""\documentclass[a4paper,12pt]{article}

% Packages
\usepackage{graphicx}
\usepackage{amsmath}
\usepackage{geometry}
\usepackage{fancyhdr}
\usepackage{setspace}
\usepackage{titlesec}  % For title formatting
\usepackage{tabularx}
\usepackage[table,xcdraw]{xcolor}  % Load the xcolor package
\geometry{margin=1in}
\setstretch{1.5}

% Define the grey color to avoid 'Undefined color' error
\definecolor{grey}{rgb}{0.5, 0.5, 0.5}

% Header and Footer
\pagestyle{fancy}
\fancyhf{}
\fancyhead[L]{COSMIAN KMS TEST SUITE}
\fancyhead[R]{\thepage}
\setlength{\headheight}{14.49998pt}  % Fix the fancyhdr warning

% Title Formatting
\titleformat{\section}{\normalfont\Large\bfseries}{\thesection}{1em}{}

% Cover Page
\title{
    \textbf{\Huge EXECUTION RESULTS OF COSMIAN KMS TEST SUITE} \\
    \author{-Automatically Generated Report-}
    \date{}
    \vspace{1cm} % Adjust vertical space
}

\begin{document}

% Title Page
\maketitle
\thispagestyle{empty}
\newpage

% Table of Contents
% Start page numbering from the Table of Contents
\setcounter{page}{1}  % Start counting from 1
\tableofcontents
\newpage

\section{Introduction}
The objective is to create a structured set of tests to ensure that the software functions as expected. The test suite will verify the functionalities and behavior of the system through well-defined test cases.

\section{Test Suite Structure}

\subsection{Tested Functionalities}
The following functionalities are chosen for defining the test suite:
\begin{enumerate}
    \item Certificates Management
    \item Symmetric Key Management
    \item Elliptic Curve Key Management (Similar to Symmetric Key Management)
    \item RSA Key Management (Similar to Symmetric Key Management)
\end{enumerate}

\subsection{Overview of Test Cases}
\begin{enumerate}
    \setlength{\itemsep}{0pt} % Adjusts space between items in the main enumerate list
    \item Certificates Management
    \begin{itemize}
        \setlength{\itemsep}{0pt} % Adjusts space between items in the itemize list
        \item Certify Certificates
        \item Export Certificates
        \item Import Certificates
        \item Revoke Certificates
        \item Destroy Certificates
    \end{itemize}
    
    \item Symmetric Keys Management
    \begin{itemize}
        \setlength{\itemsep}{0pt} % Adjusts space between items in the itemize list
        \item Create Symmetric Keys
        \item Export Symmetric Keys
        \item Import Symmetric Keys
        \item Revoke Symmetric Keys
        \item Destroy Symmetric Keys
    \end{itemize}
\end{enumerate}

\newpage
"""

latex_end = r"""
\newpage

\section{Conclusion}

The Cosmian KMS Test Suite was executed successfully, with results validating key functionalities and confirming expected behavior. All critical operations performed as intended.

\begin{center}
\textit{End of Report}
\end{center}


\end{document}
"""

def generate_latex_table_1(test_case_name, sut, version, testing_category, test_case_id, test_case_description):
    table_1 = f"""
\\subsection{{Test Case: {test_case_name}}}

\\begin{{table}}[h]
    \\centering
    \\begin{{tabularx}}{{1\\textwidth}}{{ 
      | >{{\\raggedright\\arraybackslash}}X 
      | >{{\\raggedright\\arraybackslash}}X | }}
        \\hline
        \\rowcolor{{grey!15}}
        \\multicolumn{{2}}{{|c|}}{{\\textbf{{Software Information}}}} \\\\  % Merged row with topic
        \\hline
        SUT & {sut} \\\\
        \\hline
        Version & {version} \\\\
        \\hline
        Testing Category & {testing_category} \\\\
        \\hline
        Test Case ID & {test_case_id} \\\\
        \\hline
        Test Case Name & {test_case_name} \\\\
        \\hline
        Test Case Description & {test_case_description} \\\\
        \\hline
    \\end{{tabularx}}
\\end{{table}}
"""
    return table_1

table_2_init = f"""
\\begin{{table}}[h]
    \\centering
    \\begin{{tabularx}}{{1\\textwidth}}{{ 
      | >{{\\raggedright\\arraybackslash}}X   
      | p{{2.5cm}}                            
      | p{{2.5cm}} |}}                         
        \\hline
        \\textbf{{Test Scenario}} & \\textbf{{Expected (Pass/Fail)}} & \\textbf{{Obtained (Pass/Fail)}} \\\\  
        \\hline
"""

def generate_latex_table_3(timestamp, tester, status, row_color):
    table_3 = f"""
    \\begin{{table}}[h]
        \\centering
        \\begin{{tabularx}}{{1\\textwidth}}{{ 
          | >{{\\raggedright\\arraybackslash}}X 
          | >{{\\raggedright\\arraybackslash}}X | }}
            \\hline
            Timestamp & {timestamp} \\\\
            \\hline
            Tester & {tester} \\\\
            \\hline
            \\rowcolor{{{row_color}}} % Use specified color for the row
            Status (Pass/Fail) & {status} \\\\
            \\hline
        \\end{{tabularx}}
        \\caption{{Test Case Overall Results Summary}}
        \\label{{tab:test_case_info}}
    \\end{{table}}

    \\newpage
    """
    return table_3

