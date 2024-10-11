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
    pip install clr
    pip install pythonnet
    ```
## Usage
### Import the Package
```python
import soapy
```
### Example: Retrieving AD Data
Here's an example of how to retrieve Active Directory data using the `soapy_custom_ldap` method:
- **Parameters**:
  - `server`: The domain controller to connect to.
  - `user`: The user account for authenticating against the domain.
  - `password`: The password for the user account.
  - `ldapquery`: A custom LDAP query string used to filter the AD objects (e.g., "(!soapyisepic=*)").
  - `properties`: A list of properties to retrieve for each AD object (e.g., "name", "sAMAccountName").
  - `ldapbase`: The base distinguished name (DN) for the LDAP search (e.g., "CN=Configuration").
  - `no_laps`: Boolean flag to control whether to exclude LAPS attributes from the data (default is `True`). (Local Administrator Password Solution)
- **Returns**: A List containing the retrieved AD persons.
```python
if __name__ == "__main__":
    # Set up ADWSUtils configuration
    async def main():
        data = await soapy.soapy_custom_ldap("GUESTDC01.DECEPTION.LOCAL",
                    "alex@DECEPTION.LOCAL",
                    "Hunter2!",
                    "(!soapyisepic=*)",
                    [
                        "name", "sAMAccountName", "cn", "dNSHostName", "objectSid", "objectGUID", "primaryGroupID",
                        "distinguishedName", "lastLogonTimestamp", "pwdLastSet", "servicePrincipalName", "description",
                        "operatingSystem", "sIDHistory", "nTSecurityDescriptor", "userAccountControl", "whenCreated",
                        "lastLogon", "displayName", "title", "homeDirectory",
                        "userPassword", "unixUserPassword", "scriptPath", "adminCount", "member",
                        "msDS-Behavior-Version", "msDS-AllowedToDelegateTo", "gPCFileSysPath", "gPLink", "gPOptions"
                    ],
                    "CN=Configuration")
        #The simplified Ad object just removes alot of bloat info.  
        print(simplify_ad_object(data))
        #save a json
        with open('data.json', 'w') as f:
            json.dump(data, f)
    asyncio.run(main())
```
## License
This project is currently is under GPL3 license, however the hound.dll file is based on SoapHound, please read SoapHounds rules and licences for information as this is just a SoapHound fork/wrapper for python. Made for an Education Project