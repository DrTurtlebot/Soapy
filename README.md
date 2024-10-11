![alt text](https://github.com/DrTurtlebot/SoaPy/blob/main/logo.png?raw=true)

# Soapy

Soapy is a Python package designed to interact with Active Directory (AD) via Active Directory Web Services. It came into existence due to LDAP queries being prohibited on certain clients. Its main functionality is to gather AD data, turn it in a Python List format. The package provides convenient methods for fetching and manipulating Active Directory data, using a Windows DLL that performs operations on AD. The DLL is a slightly modded version of SOAPHound where this program is just the wrapper of its functions and functionality.

## Features

- Active Directory Web Services Connection
- Retrieve Active Directory data as a List.
- Build and store AD cache files.
- Supports various parameters like user credentials and domain controllers.

### Requirements

- Python 3.8+
- .NET Framework
- The `pythonnet` library to interface with .NET DLLs
- `clr` for importing .NET assemblies

### Setup

1. Clone or download the repository.
2. Install the required Python dependencies:

    ```bash
    pip install clr
    pip install pythonnet
    ```


## Usage

### Import the Package

```python
import soapy
```

### Example: Retrieving AD Data

Here's an example of how to retrieve Active Directory data using the `soapy_get_all` method:

```python
import soapy

# Example user credentials and domain controller
user = "user@DomainAddress"
password = "Awesomepassword123"
domain_controller = "DOMAIN.CONTROLLER"
no_laps = True

# Get Active Directory data as a list of objects

ad_data = soapy.soapy_get_all(domain_controller, user, password, no_laps)

# Output the data or save it for further processing
print(ad_data)
```

### Converting to JSON

If you want to convert the resulting list into JSON format:

```python
import json
import soapy

# Example user credentials and domain controller
user = "user@DomainAddress"
password = "Awesomepassword123"
domain_controller = "DOMAIN.CONTROLLER"
no_laps = True

# Get Active Directory data as a list of objects

ad_data = soapy.soapy_get_all(domain_controller, user, password, no_laps)

# Output the data or save it for further processing
# Convert the list to JSON
ad_data_json = json.dumps(ad_data, indent=4)

# Save the JSON to a file
with open("ad_data.json", "w") as json_file:
    json_file.write(ad_data_json)
```

## Functions

### `soapy_get_all( server: str, user: str, password: str, no_laps: bool = True) -> dict`

**Description**: This is the main function of Soapy. It gathers Active Directory data, and returns it as a list of objects

- **Parameters**:
  - `server`: The domain controller to connect to.
  - `user`: The user account for authenticating against the domain.
  - `password`: The password for the user account.
  - `no_laps`: Boolean flag to control whether to exclude LAPS attributes from the data (default is `True`).

- **Returns**: A List containing the retrieved AD data.

### Example:

```python
ad_data = soapy.soapy_get_all("domain_controller","user@domain", "password", True)
print(ad_data)
```

### `soapy_get_persons( server: str, user: str, password: str, no_laps: bool = True) -> dict`

**Description**: This is a side function of Soapy. It gathers Active Directory data, and returns what it thinks are people,
WARNING these filters are custom made, so may not 100% return all persons, it does in my case but it could be weird

- **Parameters**:
  - `server`: The domain controller to connect to.
  - `user`: The user account for authenticating against the domain.
  - `password`: The password for the user account.
  - `no_laps`: Boolean flag to control whether to exclude LAPS attributes from the data (default is `True`).

- **Returns**: A List containing the retrieved AD persons.

### Example:

```python
people = soapy.soapy_get_persons("domain_controller","user@domain", "password", True)
print(people)
```

### `soapy_get_computers( server: str, user: str, password: str, no_laps: bool = True) -> dict`

**Description**: This is a side function of Soapy. It gathers Active Directory data, and returns what it thinks are computers,
WARNING these filters are custom made, so may not 100% return all computers, it does in my case but it could be weird

- **Parameters**:
  - `server`: The domain controller to connect to.
  - `user`: The user account for authenticating against the domain.
  - `password`: The password for the user account.
  - `no_laps`: Boolean flag to control whether to exclude LAPS attributes from the data (default is `True`).

- **Returns**: A List containing the retrieved AD computers.

### Example:

```python
computers = soapy.soapy_get_computers("domain_controller","user@domain", "password", True)
print(computers)
```

### `soapy_get_domain_controllers( server: str, user: str, password: str, no_laps: bool = True) -> dict`

**Description**: This is a side function of Soapy. It gathers Active Directory data, and returns what it thinks are domain controllers,
WARNING these filters are custom made, so may not 100% return all domain controllers, it does in my case but it could be weird

- **Parameters**:
  - `server`: The domain controller to connect to.
  - `user`: The user account for authenticating against the domain.
  - `password`: The password for the user account.
  - `no_laps`: Boolean flag to control whether to exclude LAPS attributes from the data (default is `True`).

- **Returns**: A List containing the retrieved AD domain controllers.

### Example:

```python
dc = soapy.soapy_get_domain_controllers("domain_controller","user@domain", "password", True)
print(dc)
```

## License

This project is currently is under GPL3 license, however the hound.dll file is based on SoapHound, please read SoapHounds rules and licences for information as this is just a SoapHound fork/wrapper for python. Made for an Education Project