import os
import hashlib
import zipfile


print("=" * 40)
print("     MALICIOUS ATTACHMENT DETECTOR")
print("=" * 40)


# ------------------------------------------------------------
# SHA-256
# ------------------------------------------------------------

def calculate_sha256(file_path):
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:
        while True:
            data = f.read(4096)

            if not data:
                break

            sha256.update(data)

    return sha256.hexdigest()


# ------------------------------------------------------------
# ACTUAL FILE TYPE DETECTION
# ------------------------------------------------------------

def detect_file_type(file_path):

    try:
        with open(file_path, "rb") as f:
            header = f.read(32)

        if header.startswith(b"MZ"):
            return "Windows Executable (EXE/DLL)"

        if header.startswith(b"%PDF"):
            return "PDF Document"

        if header.startswith(b"PK"):
            return "ZIP/Office Archive"

        if header.startswith(b"\x89PNG"):
            return "PNG Image"

        if header.startswith(b"\xff\xd8\xff"):
            return "JPEG Image"

        if header.startswith(b"GIF8"):
            return "GIF Image"

        if header.startswith(b"\x7fELF"):
            return "Linux ELF Executable"

        # Check for readable text
        try:
            text = header.decode("utf-8")

            if text.strip():
                return "Plain Text"

        except UnicodeDecodeError:
            pass

        return "Unknown"

    except Exception:
        return "Unknown"


# ------------------------------------------------------------
# EXPECTED TYPE
# ------------------------------------------------------------

def get_expected_type(extension):

    types = {

        ".exe": "Windows Executable (EXE/DLL)",
        ".dll": "Windows Executable (EXE/DLL)",

        ".pdf": "PDF Document",

        ".zip": "ZIP/Office Archive",
        ".docx": "ZIP/Office Archive",
        ".xlsx": "ZIP/Office Archive",
        ".pptx": "ZIP/Office Archive",

        ".png": "PNG Image",

        ".jpg": "JPEG Image",
        ".jpeg": "JPEG Image",

        ".gif": "GIF Image",

        ".elf": "Linux ELF Executable",

        ".txt": "Plain Text"
    }

    return types.get(extension)


# ------------------------------------------------------------
# EXTENSION MISMATCH
# ------------------------------------------------------------

def detect_extension_mismatch(extension, actual_type):

    expected_type = get_expected_type(extension)

    if expected_type is None:
        return False

    if actual_type == "Unknown":
        return False

    return expected_type != actual_type


# ------------------------------------------------------------
# ZIP ANALYSIS
# ------------------------------------------------------------

def analyze_zip(file_path):

    suspicious_files = []
    file_list = []

    try:

        with zipfile.ZipFile(file_path, "r") as archive:

            file_list = archive.namelist()

            for name in file_list:

                lower_name = name.lower()

                if lower_name.endswith((
                    ".exe",
                    ".dll",
                    ".bat",
                    ".cmd",
                    ".vbs",
                    ".vbe",
                    ".js",
                    ".ps1",
                    ".scr"
                )):

                    suspicious_files.append(name)

        return file_list, suspicious_files

    except Exception:

        return [], []


# ------------------------------------------------------------
# RISK LEVEL
# ------------------------------------------------------------

def get_risk_level(score):

    if score >= 70:
        return "HIGH"

    elif score >= 40:
        return "MEDIUM"

    return "LOW"


# ============================================================
# MAIN SCANNER
# ============================================================

file_path = input("Enter file path to scan: ").strip()


if not os.path.isfile(file_path):

    print("\nFile found: NO")
    print("Please enter a valid file path.")

else:

    print("\nFile found: YES")

    # --------------------------------------------------------
    # BASIC INFORMATION
    # --------------------------------------------------------

    file_size = os.path.getsize(file_path)
    file_extension = os.path.splitext(file_path)[1].lower()

    print("File size:", file_size, "bytes")
    print(
        "File Type:",
        file_extension if file_extension else "No extension"
    )

    # --------------------------------------------------------
    # SHA-256
    # --------------------------------------------------------

    try:

        file_hash = calculate_sha256(file_path)
        print("SHA-256:", file_hash)

    except Exception:

        print("SHA-256: Unable to calculate")

    # --------------------------------------------------------
    # ACTUAL TYPE
    # --------------------------------------------------------

    actual_type = detect_file_type(file_path)

    print("Actual File Type:", actual_type)

    # --------------------------------------------------------
    # RISK SCORE
    # --------------------------------------------------------

    risk_score = 0

    # --------------------------------------------------------
    # SUSPICIOUS EXTENSION
    # --------------------------------------------------------

    suspicious_extensions = [
        ".exe",
        ".dll",
        ".vbs",
        ".vbe",
        ".bat",
        ".cmd",
        ".js",
        ".ps1",
        ".scr"
    ]

    if file_extension in suspicious_extensions:

        risk_score += 30

    # --------------------------------------------------------
    # EXTENSION MISMATCH
    # --------------------------------------------------------

    mismatch = detect_extension_mismatch(
        file_extension,
        actual_type
    )

    if mismatch:

        expected_type = get_expected_type(file_extension)

        print("\nExtension Check: MISMATCH")

        print("Expected Type:", expected_type)

        print("Actual Type:", actual_type)

        print(
            "WARNING: File extension does not match "
            "actual file content!"
        )

        risk_score += 40

    else:

        print("Extension Check: OK")

    # --------------------------------------------------------
    # ZIP ANALYSIS
    # --------------------------------------------------------

    if actual_type == "ZIP/Office Archive":

        print("\nZIP/Archive Analysis:")

        files_inside, suspicious_files = analyze_zip(file_path)

        print("Files inside archive:", len(files_inside))

        for name in files_inside:
            print(" -", name)

        if suspicious_files:

            print(
                "\nWARNING: Suspicious file found inside archive!"
            )

            for suspicious in suspicious_files:
                print("Suspicious:", suspicious)

            risk_score += 40

        else:

            print(
                "\nNo suspicious executable files "
                "found inside archive."
            )

    # --------------------------------------------------------
    # LIMIT SCORE
    # --------------------------------------------------------

    if risk_score > 100:
        risk_score = 100

    # --------------------------------------------------------
    # FINAL RESULT
    # --------------------------------------------------------

    risk_level = get_risk_level(risk_score)

    print("\nRisk Score:", risk_score, "/100")
    print("Risk Level:", risk_level)

    if risk_level == "HIGH":

        print(
            "WARNING: Potentially dangerous file detected!"
        )

    elif risk_level == "MEDIUM":

        print(
            "CAUTION: Suspicious file detected."
        )

    else:

        print(
            "No major suspicious indicators detected."
        )

    print("\nScan completed.")
