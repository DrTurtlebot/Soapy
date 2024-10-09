import clr
import os
import json
import shutil
# pip install pythonnet is also required, but not imported.


class SoapyClient:
    def __init__(self):
        # Load the .NET assembly (adjust path if needed)
        dll_path = os.path.abspath("dlls/hound.dll")
        print(f"File found: {dll_path}")
        clr.AddReference(dll_path)

        # Import the necessary class from the DLL
        from SOAPHound import Program

        self.program = Program

    def get_cache(
        self,
        user,
        password,
        domain_controller,
        output_directory,
        cache_file_name,
        no_laps=True,
    ):
        """Builds the cache by calling the StartHound method with build_cache set to True"""
        dns_dump = False
        cert_dump = False
        bh_dump = True
        build_cache = True

        # Call the StartHound method
        self.program.StartHound(
            user,
            password,
            domain_controller,
            dns_dump,
            cert_dump,
            bh_dump,
            output_directory,
            cache_file_name,
            no_laps,
            build_cache,
        )

    def get_ad_data_dictionary(self, user, password, domain_controller, no_laps=True):
        """Fetches Active Directory data, saves it in a temporary cache folder, loads the cache files into a dictionary, and deletes the temp folder."""
        dns_dump = False
        cert_dump = False
        bh_dump = True
        build_cache = True

        # Create the temporary cache directory
        temp_cache_dir = os.path.abspath("soapy_temp_cache")
        if not os.path.exists(temp_cache_dir):
            os.makedirs(temp_cache_dir)

        # Define the cache file name and full path
        cache_file_name = os.path.join(temp_cache_dir, "ad_cache.cache")
        output_directory = temp_cache_dir

        print(f"Saving cache to: {cache_file_name}")

        # Call StartHound method from the DLL to generate the cache
        self.program.StartHound(
            user,
            password,
            domain_controller,
            dns_dump,
            cert_dump,
            bh_dump,
            output_directory,
            cache_file_name,
            no_laps,
            build_cache,
        )

        # Load the cache files into a dictionary
        cache_dict = self.load_cache_files(temp_cache_dir)

        # Clean up the temporary directory
        self.cleanup_temp_cache(temp_cache_dir)

        # Return the dictionary
        return cache_dict

    def load_cache_files(self, cache_dir):
        """Loads all cached files from the directory into a dictionary, ignoring ad_cache.cache."""
        cache_dict = {}

        # Iterate through all files in the cache directory
        for file_name in os.listdir(cache_dir):
            # Ignore the ad_cache.cache file
            if file_name == "ad_cache.cache":
                continue

            # Construct the full file path
            file_path = os.path.join(cache_dir, file_name)

            # Read the file contents (assuming the cache files are JSON)
            try:
                with open(file_path, "r") as f:
                    file_data = json.load(f)

                # Remove the "full_output" part of the file name and use it as the dictionary key
                cache_key = file_name.replace("full_output", "").replace(".json", "")
                cache_dict[cache_key] = file_data
            except Exception as e:
                print(f"Error reading file {file_name}: {e}")

        return cache_dict

    def cleanup_temp_cache(self, cache_dir):
        """Deletes all files in the temporary cache directory and then deletes the directory itself."""
        try:
            if os.path.exists(cache_dir):
                # Remove the directory and all of its contents
                shutil.rmtree(cache_dir)
                print(f"Temporary cache folder {cache_dir} deleted successfully.")
            else:
                print(f"Temporary cache folder {cache_dir} does not exist.")
        except Exception as e:
            print(f"Error cleaning up temporary cache folder {cache_dir}: {e}")
