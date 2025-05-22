# test_config_import.py
import sys
print(f"Python executable: {sys.executable}")
print(f"Python version: {sys.version}")
print(f"Python path: {sys.path}")
print("-" * 30)

print("Attempting to import from config.config...")
try:
    # Try to locate the file Python is actually looking at
    import importlib.util
    spec = importlib.util.find_spec("config.config")
    if spec and spec.origin:
        print(f"Python is trying to load config.config from: {spec.origin}")
        try:
            with open(spec.origin, 'r', encoding='utf-8') as f:
                print("\n--- Content of the file Python is loading ---")
                print(f.read())
                print("--- End of file content ---\n")
        except Exception as e:
            print(f"Could not read the file: {e}")
    else:
        print("Could not find the spec for config.config (it might not be discoverable).")


    from config import config # Import the module itself
    print("Successfully imported config.config module.")
    print("\nAttributes available in config.config:")
    found_default_report_filename_attr = False
    for attr in dir(config):
        if not attr.startswith("__"): # Filter out built-in attributes
            print(f"- {attr}")
            if attr == 'DEFAULT_REPORT_FILENAME':
                found_default_report_filename_attr = True
    
    if found_default_report_filename_attr:
        print("SUCCESS: 'DEFAULT_REPORT_FILENAME' attribute IS PRESENT in dir(config).")
    else:
        print("FAILURE: 'DEFAULT_REPORT_FILENAME' attribute IS NOT PRESENT in dir(config).")


    print("\nAttempting to access DEFAULT_REPORT_FILENAME directly via config.DEFAULT_REPORT_FILENAME:")
    # Try to access it directly to see if it's truly there
    report_filename_test = config.DEFAULT_REPORT_FILENAME
    print(f"SUCCESS: config.DEFAULT_REPORT_FILENAME = {report_filename_test}")

except ImportError as e:
    print(f"ImportError during 'from config import config' or direct access: {e}")
except AttributeError as e:
    print(f"AttributeError during direct access: {e}")
except Exception as e:
    print(f"An unexpected error occurred: {e}")

print("\n ---- Now trying the problematic import from main.py style ----")
try:
    from config.config import DEFAULT_SCAN_ARGUMENTS, DEFAULT_REPORT_FILENAME
    print("SUCCESS importing DEFAULT_SCAN_ARGUMENTS and DEFAULT_REPORT_FILENAME from config.config")
    print(f"DEFAULT_REPORT_FILENAME value (from main.py style import): {DEFAULT_REPORT_FILENAME}")
except ImportError as e:
    print(f"ImportError (main.py style): {e}")
except Exception as e:
    print(f"An unexpected error occurred during main.py style import: {e}")