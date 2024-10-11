import clr
import json
import asyncio
import xml.etree.ElementTree as ET
import os
import sys  # For dynamic DLL path resolution

# Add references to required .NET assemblies
clr.AddReference("System")
clr.AddReference("System.Net")
clr.AddReference("System.ServiceModel")
clr.AddReference("System.ServiceModel.Channels")
clr.AddReference("System.Text.RegularExpressions")
clr.AddReference("System.Xml")
clr.AddReference("System.IO")
clr.AddReference("System.ServiceModel.Security")
clr.AddReference("dlls/hound")  # Ensure the path is correct and the DLL is accessible

# Import necessary classes and modules from the added references
from System import TimeSpan, String
from System.Net import NetworkCredential
from System.ServiceModel import (
    NetTcpBinding,
    EnvelopeVersion,
    EndpointAddress,
    ChannelFactory,
    SecurityMode,
    TcpClientCredentialType,
)
from System.ServiceModel.Channels import (
    Message,
    MessageVersion,
    MessageHeader,
    AddressingVersion,
)
from System.Text.RegularExpressions import Regex, RegexOptions
from System.Xml import XmlReader
from System.IO import StringReader
from System.Security.Principal import TokenImpersonationLevel
from System.ServiceModel.Description import ClientCredentials

# Import ResourceClient and SearchClient from your DLL
from SOAPHound.ADWS import (
    ResourceClient,
    SearchClient,
)  # Ensure 'ResourceClient' and 'SearchClient' are correctly imported from your DLL


class ADWSConnector:
    def __init__(self, binding, endpoint_address, credentials):
        print("Initializing ADWSConnector...")
        self.Binding = binding
        self.EndpointAddress = endpoint_address
        self.Credentials = credentials
        self.Version = MessageVersion.CreateVersion(
            EnvelopeVersion.Soap12, AddressingVersion.WSAddressing10
        )
        print(f"Message Version set to: {self.Version}")

        print("Creating ResourceClient with binding and endpoint_address...")
        self.ResourceClient = ResourceClient(binding, endpoint_address)
        print(f"ResourceClient created: {self.ResourceClient}")

        self.UpdateCredentials(self.ResourceClient.ClientCredentials)
        self.InspectClientMethods(self.ResourceClient)  # Inspect available methods

        # Initialize SearchClient for Enumerate and Pull operations
        search_endpoint_address = EndpointAddress(
            f"net.tcp://{ADWSUtils.Server}:{ADWSUtils.Port}/ActiveDirectoryWebServices/Windows/Enumeration"
        )
        print("Creating SearchClient with binding and search_endpoint_address...")
        self.SearchClient = SearchClient(binding, search_endpoint_address)
        print(f"SearchClient created: {self.SearchClient}")

        self.UpdateCredentials(self.SearchClient.ClientCredentials)
        self.InspectClientMethods(self.SearchClient)  # Inspect available methods

    def UpdateCredentials(self, client_credentials):
        """
        Update the client credentials with impersonation level.
        Must be called before creating the channel.
        """
        try:
            print("Updating client credentials...")

            # Check if Windows credentials are available
            if (
                hasattr(client_credentials, "Windows")
                and client_credentials.Windows is not None
            ):
                print("client_credentials.Windows is available.")

                # Log current impersonation level
                current_impersonation = (
                    client_credentials.Windows.AllowedImpersonationLevel
                )
                print(f"Current AllowedImpersonationLevel: {current_impersonation}")

                # Update impersonation level
                client_credentials.Windows.AllowedImpersonationLevel = (
                    TokenImpersonationLevel.Impersonation
                )
                print("Set AllowedImpersonationLevel to Impersonation.")

                # Log credential type
                print(f"Setting ClientCredential with type: {type(self.Credentials)}")

                # Update client credential
                client_credentials.Windows.ClientCredential = self.Credentials
                print("Set ClientCredential successfully.")

                print("Credentials updated successfully.")
            else:
                error_msg = "client_credentials.Windows is not available. Cannot update credentials."
                print("Error:", error_msg)
                raise AttributeError(error_msg)
        except Exception as e:
            print(f"Failed to update credentials: {e}")
            raise

    def InspectClientMethods(self, client):
        """
        Inspect and print the available methods of the client.
        """
        print(f"Inspecting available methods in {client}...")
        methods = [
            method
            for method in dir(client)
            if callable(getattr(client, method)) and not method.startswith("_")
        ]
        print(f"Available methods in {client}: {methods}")

    async def GetAsync(self, message):
        """
        Perform an asynchronous GET request using the WCF client.
        """
        print("Preparing to perform asynchronous GET request...")
        try:
            loop = asyncio.get_event_loop()
            if hasattr(self.ResourceClient, "Get"):
                print("Calling 'Get' method on ResourceClient...")
                task = loop.run_in_executor(
                    None, self.ResourceClient.Get, message
                )  # Returns Message
                response = await task
            elif hasattr(self.ResourceClient, "GetAsync"):
                print("Calling 'GetAsync' method on ResourceClient...")
                task = self.ResourceClient.GetAsync(message)  # Returns Task[Message]
                await loop.run_in_executor(None, task.Wait)  # Wait for task to complete
                response = task.Result  # Get the Message
            else:
                error_msg = "No 'Get' or 'GetAsync' method found in ResourceClient."
                print("Error:", error_msg)
                raise AttributeError(error_msg)
            print("GET request successful.")
            # print(f"GET response: {response}")
            return response
        except Exception as e:
            print(f"GET request failed: {e}")
            raise

    async def GetADInfo(self):
        """
        Retrieve Active Directory information using a GET request.
        """
        print("Starting GetADInfo...")
        ad_info = {"DefaultNamingContext": None, "DomainName": None}

        rc_request = Message.CreateMessage(
            self.Version, "http://schemas.xmlsoap.org/ws/2004/09/transfer/Get"
        )
        print("Created rc_request message.")

        hdr1 = MessageHeader.CreateHeader(
            "instance",
            "http://schemas.microsoft.com/2008/1/ActiveDirectory",
            "ldap:389",
        )
        hdr2 = MessageHeader.CreateHeader(
            "objectReferenceProperty",
            "http://schemas.microsoft.com/2008/1/ActiveDirectory",
            "11111111-1111-1111-1111-111111111111",  # Replace with actual GUID if needed
        )
        rc_request.Headers.Add(hdr1)
        rc_request.Headers.Add(hdr2)
        print("Added headers to rc_request.")

        try:
            print("Performing GET request to retrieve AD information...")
            response = await self.GetAsync(rc_request)
            print("Received response from GET request.")

            response_document = self.MessageToXDocument(response)
            # print(f"Parsed response_document: {response_document}")

            # Correctly parse DefaultNamingContext using ElementTree methods
            ns = {
                "ad": "http://schemas.microsoft.com/2008/1/ActiveDirectory",
                "addata": "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data",
            }

            # Find the defaultNamingContext element
            default_naming_context_elements = response_document.findall(
                ".//addata:defaultNamingContext", ns
            )
            if default_naming_context_elements:
                # Get the text content of the <ad:value> element within defaultNamingContext
                default_naming_context = (
                    default_naming_context_elements[0].find("ad:value", ns).text
                )
                ad_info["DefaultNamingContext"] = default_naming_context
                ad_info["DomainName"] = ADWSConnector.ConvertLdapNamingContextToDomain(
                    default_naming_context
                )
                print(f"AD Domain Name: {ad_info['DomainName']}")
                print(f"Default Naming Context: {ad_info['DefaultNamingContext']}")
            else:
                print("Failed to parse DefaultNamingContext from response.")

            return ad_info
        except Exception as e:
            print(f"An error occurred in GetADInfo: {e}")
            raise

    async def Enumerate(self, ldapBase, ldapFilter, properties, batchSize=1000):
        """
        Perform the Enumerate operation to retrieve AD objects.

        Args:
            ldapBase (str): The base distinguished name for LDAP queries.
            ldapFilter (str): The LDAP filter string.
            properties (list): The list of properties to retrieve.
            batchSize (int): Number of entries to retrieve per batch.

        Returns:
            list: A list of AD objects retrieved from the server.
        """
        print("Starting Enumerate operation...")

        # Build the EnumerateRequest XML
        enumerate_request_xml = self.BuildEnumerateRequestXml(
            ldapBase, ldapFilter, properties
        )

        # Create the SOAP message
        request_message = Message.CreateMessage(
            self.Version,
            "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Enumerate",
            self.XmlReaderFromString(enumerate_request_xml),
        )

        # Add necessary headers
        header = MessageHeader.CreateHeader(
            "instance",
            "http://schemas.microsoft.com/2008/1/ActiveDirectory",
            "ldap:389",
        )
        request_message.Headers.Add(header)

        # Send the Enumerate request and get the response
        response = await self.EnumerateAsync(request_message)
        if response is None:
            raise Exception("Failed to get response from Enumerate request.")

        # Parse the EnumerationContext from the response
        enumeration_context = self.ParseEnumerationContext(response)
        if not enumeration_context:
            print("Error: EnumerationContext not found in Enumerate response.")
            raise Exception(
                "EnumerationContext could not be extracted from Enumerate response."
            )

        # Prepare to pull results
        ad_objects = []
        end_of_sequence = False

        while not end_of_sequence:
            pull_request_xml = self.BuildPullRequestXml(enumeration_context, batchSize)
            pull_request_message = Message.CreateMessage(
                self.Version,
                "http://schemas.xmlsoap.org/ws/2004/09/enumeration/Pull",
                self.XmlReaderFromString(pull_request_xml),
            )
            pull_request_message.Headers.Add(header)

            # Send the Pull request and get the response
            pull_response = await self.PullAsync(pull_request_message)
            if pull_response is None:
                raise Exception("Failed to get response from Pull request.")

            # **Modification Start**

            # Read the message once and parse it
            response_xml = self.MessageToXDocument(pull_response)

            # Parse AD objects from the response
            ad_objects_batch = self.ExtractADObjectsFromResponse(response_xml)
            ad_objects.extend(ad_objects_batch)

            # Check for EndOfSequence
            end_of_sequence = self.CheckEndOfSequence(response_xml)

            # **Modification End**

        print(f"Retrieved {len(ad_objects)} AD objects.")
        return ad_objects

    async def EnumerateAsync(self, message):
        """
        Send the Enumerate request using the SearchClient.

        Args:
            message (Message): The SOAP message to send.

        Returns:
            Message: The SOAP response message.
        """
        print(f"Sending Enumerate request...")
        try:
            loop = asyncio.get_event_loop()
            if hasattr(self.SearchClient, "Enumerate"):
                print("Calling 'Enumerate' method on SearchClient...")
                task = loop.run_in_executor(None, self.SearchClient.Enumerate, message)
                response = await task
            elif hasattr(self.SearchClient, "EnumerateAsync"):
                print("Calling 'EnumerateAsync' method on SearchClient...")
                task = self.SearchClient.EnumerateAsync(message)
                await loop.run_in_executor(None, task.Wait)
                response = task.Result
            else:
                error_msg = (
                    "No 'Enumerate' or 'EnumerateAsync' method found in SearchClient."
                )
                print("Error:", error_msg)
                raise AttributeError(error_msg)
            print("Enumerate request successful.")
            return response
        except Exception as e:
            print(f"Enumerate request failed: {e}")
            raise

    async def PullAsync(self, message):
        """
        Send the Pull request using the SearchClient.

        Args:
            message (Message): The SOAP message to send.

        Returns:
            Message: The SOAP response message.
        """
        print(f"Sending Pull request...")
        try:
            loop = asyncio.get_event_loop()
            if hasattr(self.SearchClient, "Pull"):
                print("Calling 'Pull' method on SearchClient...")
                task = loop.run_in_executor(None, self.SearchClient.Pull, message)
                response = await task
            elif hasattr(self.SearchClient, "PullAsync"):
                print("Calling 'PullAsync' method on SearchClient...")
                task = self.SearchClient.PullAsync(message)
                await loop.run_in_executor(None, task.Wait)
                response = task.Result
            else:
                error_msg = "No 'Pull' or 'PullAsync' method found in SearchClient."
                print("Error:", error_msg)
                raise AttributeError(error_msg)
            print("Pull request successful.")
            return response
        except Exception as e:
            print(f"Pull request failed: {e}")
            raise

    def BuildEnumerateRequestXml(self, ldapBase, ldapFilter, properties):
        """
        Build the XML for the Enumerate request.

        Args:
            ldapBase (str): The base distinguished name for LDAP queries.
            ldapFilter (str): The LDAP filter string.
            properties (list): The list of properties to retrieve.

        Returns:
            str: The XML string for the Enumerate request.
        """
        # Define namespaces
        namespaces = {
            "": "http://schemas.xmlsoap.org/ws/2004/09/enumeration",
            "ad": "http://schemas.microsoft.com/2008/1/ActiveDirectory",
            "adldap": "http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/Ldap",
            "addata": "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data",
            "adxpath": "http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/XPath",
        }

        # Create the Enumerate element
        enumerate_element = ET.Element(
            "{http://schemas.xmlsoap.org/ws/2004/09/enumeration}Enumerate",
            namespaces=namespaces,
        )

        # Add Filter
        filter_element = ET.SubElement(
            enumerate_element,
            "{http://schemas.microsoft.com/2008/1/ActiveDirectory}Filter",
            {
                "Dialect": "http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/Ldap"
            },
        )
        ldap_query_element = ET.SubElement(
            filter_element,
            "{http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/Ldap}LdapQuery",
        )
        base_object_element = ET.SubElement(
            ldap_query_element,
            "{http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/Ldap}BaseObject",
        )
        base_object_element.text = ldapBase
        filter_text_element = ET.SubElement(
            ldap_query_element,
            "{http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/Ldap}Filter",
        )
        filter_text_element.text = ldapFilter
        scope_element = ET.SubElement(
            ldap_query_element,
            "{http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/Ldap}Scope",
        )
        scope_element.text = "Subtree"

        # Add Selection
        selection_element = ET.SubElement(
            enumerate_element,
            "{http://schemas.microsoft.com/2008/1/ActiveDirectory}Selection",
            {
                "Dialect": "http://schemas.microsoft.com/2008/1/ActiveDirectory/Dialect/XPath"
            },
        )
        for prop in properties:
            selection = ET.SubElement(
                selection_element,
                "{http://schemas.microsoft.com/2008/1/ActiveDirectory}Path",
            )
            selection.text = f"/{prop}"

        # Convert XML to string
        xml_str = ET.tostring(enumerate_element, encoding="unicode")
        return xml_str

    def BuildPullRequestXml(self, enumeration_context, max_elements):
        """
        Build the XML for the Pull request.

        Args:
            enumeration_context (str): The EnumerationContext string.
            max_elements (int): The maximum number of elements to retrieve.

        Returns:
            str: The XML string for the Pull request.
        """
        # Define namespaces
        namespaces = {
            "": "http://schemas.xmlsoap.org/ws/2004/09/enumeration",
            "ad": "http://schemas.microsoft.com/2008/1/ActiveDirectory",
        }

        # Create the Pull element
        pull_element = ET.Element(
            "{http://schemas.xmlsoap.org/ws/2004/09/enumeration}Pull",
            namespaces=namespaces,
        )

        # Add EnumerationContext
        enum_context_element = ET.SubElement(
            pull_element,
            "{http://schemas.xmlsoap.org/ws/2004/09/enumeration}EnumerationContext",
        )
        enum_context_element.text = enumeration_context

        # Add MaxElements
        max_elements_element = ET.SubElement(
            pull_element,
            "{http://schemas.xmlsoap.org/ws/2004/09/enumeration}MaxElements",
        )
        max_elements_element.text = str(max_elements)

        # Convert XML to string
        xml_str = ET.tostring(pull_element, encoding="unicode")
        return xml_str

    def ParseEnumerationContext(self, response_message):
        """
        Parse the EnumerationContext from the Enumerate response.

        Args:
            response_message (Message): The response message from Enumerate.

        Returns:
            str: The EnumerationContext string.
        """
        print("Parsing EnumerationContext from response...")
        response_xml = self.MessageToXDocument(response_message)
        ns = {"a": "http://schemas.xmlsoap.org/ws/2004/09/enumeration"}
        enumeration_context_elements = response_xml.findall(
            ".//a:EnumerationContext", ns
        )
        if enumeration_context_elements:
            enumeration_context = enumeration_context_elements[0].text
            # print(f"EnumerationContext: {enumeration_context}")
            return enumeration_context
        else:
            print("Error: EnumerationContext not found in response.")
            return None

    def ExtractADObjectsFromResponse(self, response_xml):
        """
        Extract AD objects from the Pull response.

        Args:
            response_xml (Element): The parsed XML of the response.

        Returns:
            list: A list of AD objects (dictionaries).
        """
        print("Extracting AD objects from Pull response...")
        ns = {
            "a": "http://schemas.xmlsoap.org/ws/2004/09/enumeration",
            "ad": "http://schemas.microsoft.com/2008/1/ActiveDirectory",
            "addata": "http://schemas.microsoft.com/2008/1/ActiveDirectory/Data",
        }
        ad_objects = []

        items = response_xml.findall(".//a:Items", ns)
        if items:
            for item in items[0]:
                ad_object = self.ParseXmlToDict(item)
                ad_objects.append(ad_object)
        else:
            print("Warning: No AD objects found in Pull response.")
        return ad_objects

    def CheckEndOfSequence(self, response_xml):
        """
        Check if the EndOfSequence element is present in the response.

        Args:
            response_xml (Element): The parsed XML of the response.

        Returns:
            bool: True if EndOfSequence is present, False otherwise.
        """
        print("Checking for EndOfSequence in Pull response...")
        ns = {"a": "http://schemas.xmlsoap.org/ws/2004/09/enumeration"}
        eos_elements = response_xml.findall(".//a:EndOfSequence", ns)
        return len(eos_elements) > 0

    @staticmethod
    def XmlReaderFromString(xml):
        """
        Create an XmlReader from an XML string.
        """
        print("Creating XmlReader from string...")
        return XmlReader.Create(StringReader(xml))

    def MessageToXDocument(self, message):
        """
        Convert the WCF Message to an ElementTree XML document.
        """
        print("Converting WCF Message to XML document...")
        try:
            # Create a buffered copy of the message
            buffered_copy = message.CreateBufferedCopy(int(1e6))
            message_copy = buffered_copy.CreateMessage()

            body_reader = message_copy.GetReaderAtBodyContents()
            body_xml = body_reader.ReadOuterXml()
            # print(f"Body XML: {body_xml}")
            root = ET.fromstring(body_xml)

            # Replace the original message with the buffered copy for further use if needed
            self.buffered_message = buffered_copy.CreateMessage()
            return root
        except ET.ParseError as e:
            print(f"XML parsing failed: {e}")
            raise
        except Exception as e:
            print(f"Failed to convert message to document: {e}")
            raise

    @staticmethod
    def ParseXmlToDict(element):
        """
        Recursive function to convert XML elements to a dictionary, handling attributes and multiple children,
        while stripping namespaces from tags.
        """
        # Strip namespace from tag
        tag = element.tag
        if "}" in tag:
            tag = tag.split("}", 1)[1]

        data = {}
        # Handle attributes
        if element.attrib:
            data.update(
                {
                    f"@{k.split('}')[-1] if '}' in k else k}": v
                    for k, v in element.attrib.items()
                }
            )

        # Handle child elements
        children = list(element)
        if children:
            dd = {}
            for child in children:
                child_data = ADWSConnector.ParseXmlToDict(child)
                child_tag = child.tag.split("}")[-1] if "}" in child.tag else child.tag
                if child_tag in dd:
                    if isinstance(dd[child_tag], list):
                        dd[child_tag].append(child_data)
                    else:
                        dd[child_tag] = [dd[child_tag], child_data]
                else:
                    dd[child_tag] = child_data
            data.update(dd)
        else:
            # Handle text
            text = element.text.strip() if element.text else ""
            data = text

        return data

    @staticmethod
    def ConvertLdapNamingContextToDomain(ldap_context):
        """
        Convert LDAP naming context to domain format.
        """
        # print(f"Converting LDAP naming context to domain: {ldap_context}")
        if not ldap_context:
            return ""
        components = ldap_context.split(",")
        domain_components = [
            c.replace("DC=", "") for c in components if c.startswith("DC=")
        ]
        domain = ".".join(domain_components)
        # print(f"Converted domain: {domain}")
        return domain

    def Close(self):
        """
        Close the clients to release resources.
        """
        print("Closing clients...")
        try:
            self.ResourceClient.Close()
            self.SearchClient.Close()
            print("Clients closed successfully.")
        except Exception as e:
            print(f"An error occurred while closing the clients: {e}")
            self.ResourceClient.Abort()
            self.SearchClient.Abort()


class ADWSUtils:
    Server = None
    Port = None
    Credential = NetworkCredential("", "")
    nolaps = None

    DCReplaceRegex = Regex("DC=", RegexOptions.IgnoreCase | RegexOptions.Compiled)

    @staticmethod
    async def GetObjects(label):
        """
        Retrieve AD objects based on the specified label.
        """
        print(f"GetObjects called with label: {label}")
        objects = await ADWSUtils.RunEnumeration(label)
        simplified_objects = [simplify_ad_object(obj) for obj in objects]
        return simplified_objects

    @staticmethod
    async def RunEnumeration(label):
        """
        Internal method to perform the enumeration.
        """
        print(f"RunEnumeration called with label: {label}")
        return await ADWSUtils.GetObjectsInternal(label)

    @staticmethod
    async def GetObjectsInternal(label):
        """
        Internal function to handle the enumeration logic.
        """
        print(f"GetObjectsInternal called with label: {label}")

        # Define LDAP queries and properties based on the label
        ldapquery = ""
        properties = []
        banner = ""
        ldapbase = ""

        if label == "dns":
            banner = "Gathering DNS data"
            ldapquery = "(&(ObjectClass=dnsNode))"
            properties = ["Name", "dnsRecord"]
            ldapbase = "CN=MicrosoftDNS,DC=DomainDnsZones,"
        elif label == "cache":
            banner = "Generating cache"
            ldapquery = "(!soapyisepic=*)"
            properties = ["objectSid", "objectGUID", "distinguishedName"]
        elif label == "pkicache":
            banner = "Gathering PKI cache"
            ldapquery = "(!soapyisepic=*)"
            properties = ["name", "certificateTemplates"]
            ldapbase = "CN=Configuration,"
        elif label == "pkidata":
            banner = "Gathering PKI data"
            ldapquery = "(!soapyisepic=*)"
            properties = [
                "name",
                "displayName",
                "nTSecurityDescriptor",
                "objectGUID",
                "dNSHostName",
                "certificateTemplates",
                "cACertificate",
                "msPKI-Minimal-Key-Size",
                "msPKI-Certificate-Name-Flag",
                "msPKI-Enrollment-Flag",
                "msPKI-Private-Key-Flag",
                "pKIExtendedKeyUsage",
                "pKIOverlapPeriod",
                "pKIExpirationPeriod",
            ]
            ldapbase = "CN=Configuration,"
        elif label == "ad":
            banner = "Gathering AD data"
            ldapquery = "(!soapyisepic=*)"  # LDAP query string
            if ADWSUtils.nolaps:
                properties = [
                    "name",
                    "sAMAccountName",
                    "cn",
                    "dNSHostName",
                    "objectSid",
                    "objectGUID",
                    "primaryGroupID",
                    "distinguishedName",
                    "lastLogonTimestamp",
                    "pwdLastSet",
                    "servicePrincipalName",
                    "description",
                    "operatingSystem",
                    "sIDHistory",
                    "nTSecurityDescriptor",
                    "userAccountControl",
                    "whenCreated",
                    "lastLogon",
                    "displayName",
                    "title",
                    "homeDirectory",
                    "userPassword",
                    "unixUserPassword",
                    "scriptPath",
                    "adminCount",
                    "member",
                    "msDS-Behavior-Version",
                    "msDS-AllowedToDelegateTo",
                    "gPCFileSysPath",
                    "gPLink",
                    "gPOptions",
                ]
            else:
                properties = [
                    "name",
                    "sAMAccountName",
                    "cn",
                    "dNSHostName",
                    "objectSid",
                    "objectGUID",
                    "primaryGroupID",
                    "distinguishedName",
                    "lastLogonTimestamp",
                    "pwdLastSet",
                    "servicePrincipalName",
                    "description",
                    "operatingSystem",
                    "sIDHistory",
                    "nTSecurityDescriptor",
                    "userAccountControl",
                    "whenCreated",
                    "lastLogon",
                    "ms-MCS-AdmPwdExpirationTime",
                    "displayName",
                    "title",
                    "homeDirectory",
                    "userPassword",
                    "unixUserPassword",
                    "scriptPath",
                    "adminCount",
                    "member",
                    "msDS-Behavior-Version",
                    "msDS-AllowedToDelegateTo",
                    "gPCFileSysPath",
                    "gPLink",
                    "gPOptions",
                ]
        elif label == "domaintrusts":
            banner = "Gathering DomainTrusts data"
            ldapquery = "(trustType=*)"
            properties = [
                "trustAttributes",
                "trustDirection",
                "name",
                "securityIdentifier",
            ]
        elif label == "domains":
            banner = "Gathering Domains data"
            ldapquery = "(ms-DS-MachineAccountQuota=*)"
            properties = [
                "name",
                "sAMAccountName",
                "cn",
                "dNSHostName",
                "objectSid",
                "objectGUID",
                "primaryGroupID",
                "distinguishedName",
                "lastLogonTimestamp",
                "pwdLastSet",
                "servicePrincipalName",
                "description",
                "operatingSystem",
                "sIDHistory",
                "nTSecurityDescriptor",
                "userAccountControl",
                "whenCreated",
                "lastLogon",
                "displayName",
                "title",
                "homeDirectory",
                "userPassword",
                "unixUserPassword",
                "scriptPath",
                "adminCount",
                "member",
                "msDS-Behavior-Version",
                "msDS-AllowedToDelegateTo",
                "gPCFileSysPath",
                "gPLink",
                "gPOptions",
            ]
        elif label == "nonchars":
            banner = "Gathering non alphanumeric objects"
            ldapquery = "(&(cn=*)(!(cn=a*))(!(cn=b*))(!(cn=c*))(!(cn=d*))(!(cn=e*))(!(cn=f*))(!(cn=g*))(!(cn=h*))(!(cn=i*))(!(cn=j*))(!(cn=k*))(!(cn=l*))(!(cn=m*))(!(cn=n*))(!(cn=o*))(!(cn=p*))(!(cn=q*))(!(cn=r*))(!(cn=s*))(!(cn=t*))(!(cn=u*))(!(cn=v*))(!(cn=w*))(!(cn=x*))(!(cn=y*))(!(cn=z*))(!(cn=0*))(!(cn=1*))(!(cn=2*))(!(cn=3*))(!(cn=4*))(!(cn=5*))(!(cn=6*))(!(cn=7*))(!(cn=8*))(!(cn=9*)))"
            properties = [
                "name",
                "sAMAccountName",
                "cn",
                "dNSHostName",
                "objectSid",
                "objectGUID",
                "primaryGroupID",
                "distinguishedName",
                "lastLogonTimestamp",
                "pwdLastSet",
                "servicePrincipalName",
                "description",
                "operatingSystem",
                "sIDHistory",
                "nTSecurityDescriptor",
                "userAccountControl",
                "whenCreated",
                "lastLogon",
                "displayName",
                "title",
                "homeDirectory",
                "userPassword",
                "unixUserPassword",
                "scriptPath",
                "adminCount",
                "member",
                "msDS-Behavior-Version",
                "msDS-AllowedToDelegateTo",
                "gPCFileSysPath",
                "gPLink",
                "gPOptions",
            ]
        else:
            banner = f"Gathering autosplit data: {label}"
            ldapquery = label
            properties = [
                "name",
                "sAMAccountName",
                "cn",
                "dNSHostName",
                "objectSid",
                "objectGUID",
                "primaryGroupID",
                "distinguishedName",
                "lastLogonTimestamp",
                "pwdLastSet",
                "servicePrincipalName",
                "description",
                "operatingSystem",
                "sIDHistory",
                "nTSecurityDescriptor",
                "userAccountControl",
                "whenCreated",
                "lastLogon",
                "ms-MCS-AdmPwdExpirationTime",
                "displayName",
                "title",
                "homeDirectory",
                "userPassword",
                "unixUserPassword",
                "scriptPath",
                "adminCount",
                "member",
                "msDS-Behavior-Version",
                "msDS-AllowedToDelegateTo",
                "gPCFileSysPath",
                "gPLink",
                "gPOptions",
            ]

        print("-------------")
        print(f"Banner: {banner}")

        # Initialize the ADWSConnector
        print(
            f"Creating ADWSConnector with Server: {ADWSUtils.Server} and Credentials: {ADWSUtils.Credential}."
        )

        # Configure the binding with explicit SecurityMode and ClientCredentialType
        binding = NetTcpBinding()
        binding.Security.Mode = SecurityMode.Transport
        binding.Security.Transport.ClientCredentialType = (
            TcpClientCredentialType.Windows
        )
        binding.MaxBufferSize = 1073741824  # 1 GB
        binding.MaxReceivedMessageSize = 1073741824  # 1 GB

        # Set ReaderQuotas
        binding.ReaderQuotas.MaxDepth = 64
        binding.ReaderQuotas.MaxArrayLength = 2147483647
        binding.ReaderQuotas.MaxStringContentLength = 2147483647
        binding.ReaderQuotas.MaxNameTableCharCount = 2147483647
        binding.ReaderQuotas.MaxBytesPerRead = 2147483647

        resource_endpoint_address = EndpointAddress(
            f"net.tcp://{ADWSUtils.Server}:{ADWSUtils.Port}/ActiveDirectoryWebServices/Windows/Resource"
        )

        # Create the connector instance
        print("Instantiating ADWSConnector...")
        connector = ADWSConnector(
            binding, resource_endpoint_address, ADWSUtils.Credential
        )

        try:
            # Retrieve AD information
            print("Retrieving AD domain information...")
            domainInfo = await connector.GetADInfo()
            print("Domain Info:")
            # print(domainInfo)

            if not domainInfo["DefaultNamingContext"]:
                print(
                    "Error: Failed to retrieve DefaultNamingContext. Exiting enumeration."
                )
                return {}

            # Update ldapbase and log the new value
            ldapbase += domainInfo["DefaultNamingContext"]
            # print(f"Updated ldapbase: {ldapbase}")

            # Execute ADWS Enumeration
            # print(f"Enumerating AD objects with ldapbase: {ldapbase}, ldapquery: {ldapquery}, properties: {', '.join(properties)}")
            adobjects = await connector.Enumerate(ldapbase, ldapquery, properties)

            # Log completion of the ADWS request
            print(f"{banner} complete")

            return adobjects
        finally:
            connector.Close()


def extract_value(value):
    """
    Recursively extract the 'value' from nested dictionaries and lists.
    """
    if isinstance(value, dict):
        # If the value is a dictionary with a 'value' key, extract it
        if "value" in value:
            return extract_value(value["value"])
        else:
            # No 'value' key, return an empty string or handle as needed
            return ""
    elif isinstance(value, list):
        # If the value is a list, process each item
        return [extract_value(item) for item in value]
    else:
        # Base case: value is a primitive type (e.g., str, int)
        return value


def simplify_ad_object(obj):
    """
    Simplify an AD object by extracting values from nested structures.
    """
    simplified_obj = {}
    for attr, value in obj.items():
        simplified_value = extract_value(value)
        # If the simplified_value is a list with one element, unpack it
        if isinstance(simplified_value, list) and len(simplified_value) == 1:
            simplified_value = simplified_value[0]
        simplified_obj[attr] = simplified_value
    return simplified_obj


async def soapy_get_computers(server, user, password, nolaps=True):
    ADWSUtils.Server = server
    ADWSUtils.Port = 9389
    ADWSUtils.Credential = NetworkCredential(user, password)
    ADWSUtils.nolaps = nolaps

    objects = await ADWSUtils.GetObjects("ad")
    computers = [obj for obj in objects if soapy_internal_is_computer(obj)]
    return computers


async def soapy_get_domain_controllers(server, user, password, nolaps=True):
    ADWSUtils.Server = server
    ADWSUtils.Port = 9389
    ADWSUtils.Credential = NetworkCredential(user, password)
    ADWSUtils.nolaps = nolaps

    # Retrieve AD objects
    objects = await ADWSUtils.GetObjects("ad")

    # Filter to get only domain controller objects
    domain_controllers = [
        obj for obj in objects if soapy_internal_is_domain_controller(obj)
    ]
    return domain_controllers


def soapy_internal_is_domain_controller(obj):
    # Check 'objectClass'
    object_classes = obj.get("objectClass")
    is_computer = False
    if object_classes:
        if isinstance(object_classes, list):
            if "computer" in [oc.lower() for oc in object_classes]:
                is_computer = True
        elif isinstance(object_classes, str):
            if object_classes.lower() == "computer":
                is_computer = True

    if not is_computer:
        return False

    # Check 'userAccountControl' for SERVER_TRUST_ACCOUNT flag (8192)
    user_account_control = obj.get("userAccountControl")
    if user_account_control:
        user_account_control = int(user_account_control)
        if user_account_control & 8192:
            return True

    return False


def soapy_internal_is_computer(obj):
    # Helper function to extract values from an attribute
    def get_values(attr):
        if isinstance(attr, dict):
            value = attr.get("value")
            if isinstance(value, list):
                return value
            elif value is not None:
                return [value]
        elif isinstance(attr, list):
            values = []
            for item in attr:
                if isinstance(item, dict):
                    val = item.get("value")
                    if isinstance(val, list):
                        values.extend(val)
                    elif val is not None:
                        values.append(val)
                elif isinstance(item, str):
                    values.append(item)
            return values
        elif isinstance(attr, str):
            return [attr]
        return []

    # Check 'objectClass'
    object_classes = get_values(obj.get("objectClass"))
    for oc in object_classes:
        if oc.lower() == "computer":
            return True

    # Check 'sAMAccountType'
    sAMAccountTypes = get_values(obj.get("sAMAccountType"))
    for sat in sAMAccountTypes:
        if sat == "805306369":  # sAMAccountType for computers
            return True

    # Check 'objectCategory'
    object_categories = get_values(obj.get("objectCategory"))
    for oc in object_categories:
        if "CN=Computer" in oc:
            return True

    return False


async def soapy_get_persons(server, user, password, nolaps=True):
    ADWSUtils.Server = server
    ADWSUtils.Port = 9389
    ADWSUtils.Credential = NetworkCredential(user, password)
    ADWSUtils.nolaps = nolaps

    # Retrieve AD objects
    objects = await ADWSUtils.GetObjects("ad")

    # Filter to get only person (user) objects
    persons = [obj for obj in objects if soapy_internal_is_person(obj)]
    return persons


def soapy_internal_is_person(obj):
    # Check 'objectClass'
    object_classes = obj.get("objectClass")
    if object_classes:
        if isinstance(object_classes, list):
            if "user" in [oc.lower() for oc in object_classes]:
                return True
        elif isinstance(object_classes, str):
            if object_classes.lower() == "user":
                return True

    # Check 'sAMAccountType'
    sAMAccountType = obj.get("sAMAccountType")
    if sAMAccountType == "805306368":  # sAMAccountType for users
        return True

    # Check 'objectCategory'
    object_category = obj.get("objectCategory")
    if object_category and "CN=Person" in object_category:
        return True

    return False


async def soapy_get_all(server, user, password, nolaps=True):
    ADWSUtils.Server = server
    ADWSUtils.Port = 9389
    ADWSUtils.Credential = NetworkCredential(user, password)
    ADWSUtils.nolaps = nolaps

    # Retrieve AD objects
    objects = await ADWSUtils.GetObjects("ad")
    # Filter to get only OU objects
    return objects


# Example usage
if __name__ == "__main__":
    # Set up ADWSUtils configuration
    async def main():
        computers = await soapy_get_all(
            "GREAT.EXAMPLE.LOCAL", "Cool@EXAMPLE.LOCAL", "epicpassword2!"
        )
        with open("data.json", "w") as f:
            json.dump(computers, f)

    asyncio.run(main())
