# IAM Access Analyzer Findings Exporter

This Python script retrieves findings from an AWS IAM Access Analyzer analyzer and exports them to a CSV file.

## Prerequisites

- Python 3.x installed
- AWS credentials configured with appropriate permissions to access IAM Access Analyzer

## Setup

1. Clone or download the repository.
2. Install the required Python packages by running:

3. Create a `config.ini` file in the same directory as the Python script, with the following content:

```ini
[access_analyzer]
analyzer_arn = <your_analyzer_arn>
```
Replace `<your_analyzer_arn>` with the Amazon Resource Name (ARN) of your IAM Access Analyzer analyzer.
## Usage
1. Open a terminal or command prompt and navigate to the directory containing the Python script.
2. Run the script with the following command:
```pip
python list_findings.py
```

The script will retrieve the findings from the specified IAM Access Analyzer analyzer and export them to a CSV file named 
`findings.csv` in the same directory. [Finding example CSV file.](findings.sample.csv)

