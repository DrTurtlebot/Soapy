
![alt text](https://github.com/DrTurtlebot/SoaPy/blob/main/logo.png?raw=true)
# Soapy
Soapy is a Python package designed to interact with Active Directory (AD) via Active Directory Web Services. It came into existence due to LDAP queries being prohibited on certain clients. Its main functionality is to run custom LDAP requests via the Active Directory Web Services protocol. 

## Features
- Active Directory Web Services Connection
- Retrieve Active Directory data as a List of objects.
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
    pip install pythonnet
    ```

Note: The `clr` module is part of the `pythonnet` library, so installing `pythonnet` will include the `clr` module.

### Usage
#### Import the Package
You will first need to create a connection using the `Connection` class. Then, you can perform LDAP queries.

```python
from soapy import Connection
```

#### Example: Retrieving AD Data with a Connection Class
Here's an example of how to retrieve Active Directory data using the `Connection` class:

- **Parameters**:
  - `server`: The domain controller to connect to.
  - `user`: The user account for authenticating against the domain.
  - `password`: The password for the user account.
  - `ldapquery`: A custom LDAP query string used to filter the AD objects (e.g., "(!soapyisepic=*)").
  - `properties`: A list of properties to retrieve for each AD object (e.g., "name", "sAMAccountName").
  - `ldapbase`: The base distinguished name (DN) for the LDAP search (e.g., "CN=Configuration").
  - `nolaps`: Boolean flag to control whether to exclude LAPS attributes from the data (default is `True`). (Local Administrator Password Solution)

- **Returns**: A List containing the retrieved AD objects.

```python
from soapy import Connection

if __name__ == "__main__":
    async def main():
        # Create a connection to the server
        client = Connection(
            server="GUESTDC01.COOLCORP.LOCAL",
            user="alex@COOLCORP.LOCAL",
            password="SuperPassword123"
        )

        # Perform an LDAP query
        computers = await client.soapy_custom_ldap(
            ldapquery="(!soapyisepic=*)",
            properties=[
                "name", "sAMAccountName", "cn", "dNSHostName", "objectSid", "objectGUID", "primaryGroupID",
                "distinguishedName", "lastLogonTimestamp", "pwdLastSet", "servicePrincipalName", "description",
                "operatingSystem", "sIDHistory", "nTSecurityDescriptor", "userAccountControl", "whenCreated",
                "lastLogon", "displayName", "title", "homeDirectory",
                "userPassword", "unixUserPassword", "scriptPath", "adminCount", "member",
                "msDS-Behavior-Version", "msDS-AllowedToDelegateTo", "gPCFileSysPath", "gPLink", "gPOptions"
            ],
            ldapbase="CN=Configuration"
        )

        # Print the results
        print(computers)

        # Save the result to a JSON file
        with open('data.json', 'w') as f:
            json.dump(computers, f)

    asyncio.run(main())
```

## License
Please note that this code is free to use and modify. It is based on how SoapHound handles communication with C#, but it has been adapted for Python. A small portion of the SoapHound C# code is referenced in the DLL. I'm unsure about the legality of using it, as the net.tcp binding might be proprietary. Therefore, for legal reasons, I cannot confirm that using it is permissible. I'm sharing this code as an educational project to explore Active Directory Web Services (ADWS), GSS-API communications, and the SOAP protocol.
