![alt text](https://github.com/DrTurtlebot/SoaPy/blob/main/logo.png?raw=true)

# Soapy

Soapy is a Python package designed to interact with Active Directory (AD) via .NET DLL integration. Its main functionality is to gather AD data, cache it, and return it in a Python dictionary format. The package provides convenient methods for fetching and manipulating Active Directory data, using a Windows DLL that performs operations on AD.

## Features

- Retrieve Active Directory data as a dictionary.
- Build and store AD cache files.
- Supports various parameters like user credentials and domain controllers.
- Easily converts AD data to JSON format for further use.

## Installation

### Requirements

- Python 3.8+
- .NET Framework
- The `pythonnet` library to interface with .NET DLLs
- `clr` for importing .NET assemblies

### Setup

1. Clone or download the repository.
2. Install the required Python dependencies:

    ```bash
    pip install pythonnet
    ```


## Usage

### Import the Package

```python
from soapy import get_ad_data_dictionary
```

### Example: Retrieving AD Data

Here's an example of how to retrieve Active Directory data using the `get_ad_data_dictionary` method:

```python
from soapy import get_ad_data_dictionary

# Example user credentials and domain controller
user = "user@DomainAddress"
password = "Awesomepassword123"
domain_controller = "DOMAIN.CONTROLLER"
no_laps = True

# Get Active Directory data as a dictionary
ad_data = get_ad_data_dictionary(user, password, domain_controller, no_laps)

# Output the data or save it for further processing
print(ad_data)
```

### Converting to JSON

If you want to convert the resulting dictionary into JSON format:

```python
import json
from soapy import get_ad_data_dictionary

# Example credentials and domain controller
user = "user@DomainAddress"
password = "Awesomepassword123"
domain_controller = "DOMAIN.CONTROLLER"

# Get the AD data as a dictionary
ad_data = get_ad_data_dictionary(user, password, domain_controller)

# Convert the dictionary to JSON
ad_data_json = json.dumps(ad_data, indent=4)

# Save the JSON to a file
with open("ad_data.json", "w") as json_file:
    json_file.write(ad_data_json)
```

## Functions

### `get_ad_data_dictionary(user: str, password: str, domain_controller: str, no_laps: bool = True) -> dict`

**Description**: This is the main function of Soapy. It gathers Active Directory data, caches it, and returns it as a Python dictionary.

- **Parameters**:
  - `user`: The user account for authenticating against the domain.
  - `password`: The password for the user account.
  - `domain_controller`: The domain controller to connect to.
  - `no_laps`: Boolean flag to control whether to exclude LAPS attributes from the data (default is `True`).

- **Returns**: A dictionary containing the retrieved AD data.

### Example:

```python
ad_data = get_ad_data_dictionary("user@domain", "password", "domain_controller", True)
print(ad_data)
```

## Cache Management

- **Cache Location**: The cache files are stored temporarily in the `/soapy_temp_cache/` directory during runtime.
- **Cache Cleanup**: All cache files are deleted after processing, and the folder is removed to prevent leftover files from cluttering the directory.

## License

This project is currently is under GPL3 license, however the hound.dll file is based on SoapHound, please read SoapHounds rules and licences for information as this is just a SoapHound fork/wrapper for python. 