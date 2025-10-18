@echo off
setlocal enabledelayedexpansion

:: Ensure JAVA_HOME is set and jar command is available
where jar >nul 2>&1
if %ERRORLEVEL% neq 0 (
    echo ❌ Error: 'jar' command not found. Ensure JAVA_HOME is set and JDK is installed.
    pause
    exit /b 1
)

:: Prompt for main JAR
set /p MAIN_JAR="Enter the full path of the main JAR file: "
if not exist "!MAIN_JAR!" (
    echo ❌ Main JAR not found: !MAIN_JAR!
    pause
    exit /b 1
)

:: Prompt for lib folder
set /p LIB_DIR="Enter the path to the folder containing dependency JARs: "
if not exist "!LIB_DIR!" (
    echo ❌ Lib folder not found: !LIB_DIR!
    pause
    exit /b 1
)

:: Prompt for output JAR path
set /p OUTPUT_JAR="Enter the full path and name for the output fat JAR: "
if "!OUTPUT_JAR!"=="" (
    echo ❌ Output JAR path cannot be empty!
    pause
    exit /b 1
)

:: Prompt for optional main class
set /p MAIN_CLASS="Enter the main class name (leave blank to use existing manifest): "

:: Set up temporary directory with unique name
set "TEMP_DIR=%~dp0fatjar_temp_%RANDOM%"
if exist "!TEMP_DIR!" (
    echo 🧹 Cleaning up existing temp directory...
    rmdir /s /q "!TEMP_DIR!" || (
        echo ❌ Failed to clean up temp directory: !TEMP_DIR!
        pause
        exit /b 1
    )
)

:: Create temporary directory
mkdir "!TEMP_DIR!" || (
    echo ❌ Failed to create temp directory: !TEMP_DIR!
    pause
    exit /b 1
)

:: Extract main JAR
echo.
echo 🔍 Extracting main JAR: !MAIN_JAR!
cd /d "!TEMP_DIR!"
jar xf "!MAIN_JAR!" || (
    echo ❌ Failed to extract main JAR: !MAIN_JAR!
    cd /d "%~dp0"
    rmdir /s /q "!TEMP_DIR!"
    pause
    exit /b 1
)

:: Extract dependency JARs
echo.
echo 🔍 Extracting dependency JARs from: !LIB_DIR!
set "DEPENDENCY_COUNT=0"
for %%F in ("!LIB_DIR!\*.jar") do (
    echo - Extracting: %%~nxF
    jar xf "%%F" || (
        echo ❌ Failed to extract dependency JAR: %%F
        cd /d "%~dp0"
        rmdir /s /q "!TEMP_DIR!"
        pause
        exit /b 1
    )
    set /a DEPENDENCY_COUNT+=1
)
if !DEPENDENCY_COUNT! equ 0 (
    echo ⚠️ Warning: No dependency JARs found in: !LIB_DIR!
)

:: Remove signature files to avoid invalid signature errors
echo.
echo 🧹 Removing signature files from META-INF...
if exist "!TEMP_DIR!\META-INF\*.SF" (
    del /q "!TEMP_DIR!\META-INF\*.SF" || (
        echo ❌ Failed to remove .SF signature files!
        cd /d "%~dp0"
        rmdir /s /q "!TEMP_DIR!"
        pause
        exit /b 1
    )
)
if exist "!TEMP_DIR!\META-INF\*.DSA" (
    del /q "!TEMP_DIR!\META-INF\*.DSA" || (
        echo ❌ Failed to remove .DSA signature files!
        cd /d "%~dp0"
        rmdir /s /q "!TEMP_DIR!"
        pause
        exit /b 1
    )
)
if exist "!TEMP_DIR!\META-INF\*.RSA" (
    del /q "!TEMP_DIR!\META-INF\*.RSA" || (
        echo ❌ Failed to remove .RSA signature files!
        cd /d "%~dp0"
        rmdir /s /q "!TEMP_DIR!"
        pause
        exit /b 1
    )
)

:: Go back to script directory
cd /d "%~dp0"

:: Handle manifest
set "MANIFEST_FILE=!TEMP_DIR!\META-INF\MANIFEST.MF"
if not "!MAIN_CLASS!"=="" (
    echo.
    echo 🛠️ Creating custom manifest with Main-Class: !MAIN_CLASS!
    :: Ensure META-INF directory exists
    if not exist "!TEMP_DIR!\META-INF" (
        mkdir "!TEMP_DIR!\META-INF" || (
            echo ❌ Failed to create META-INF directory!
            rmdir /s /q "!TEMP_DIR!"
            pause
            exit /b 1
        )
    )

    :: Create manifest file directly
    > "!MANIFEST_FILE!" (
        echo.Manifest-Version: 1.0
        echo.Main-Class: !MAIN_CLASS!
        echo.
    ) || (
        echo ❌ Failed to create manifest file: !MANIFEST_FILE!
        rmdir /s /q "!TEMP_DIR!"
        pause
        exit /b 1
    )

    :: Verify manifest file exists
    if not exist "!MANIFEST_FILE!" (
        echo ❌ Manifest file was not created: !MANIFEST_FILE!
        rmdir /s /q "!TEMP_DIR!"
        pause
        exit /b 1
    )

    :: Create fat JAR with custom manifest
    echo 📦 Building fat JAR with custom manifest...
    jar cfm "!OUTPUT_JAR!" "!MANIFEST_FILE!" -C "!TEMP_DIR!" . || (
        echo ❌ Failed to create fat JAR with custom manifest!
        rmdir /s /q "!TEMP_DIR!"
        pause
        exit /b 1
    )
) else (
    :: Use existing manifest if available
    if exist "!MANIFEST_FILE!" (
        echo.
        echo 📦 Building fat JAR with existing manifest...
        jar cfm "!OUTPUT_JAR!" "!MANIFEST_FILE!" -C "!TEMP_DIR!" . || (
            echo ❌ Failed to create fat JAR with existing manifest!
            rmdir /s /q "!TEMP_DIR!"
            pause
            exit /b 1
        )
    ) else (
        echo.
        echo 📦 Building fat JAR without manifest...
        jar cf "!OUTPUT_JAR!" -C "!TEMP_DIR!" . || (
            echo ❌ Failed to create fat JAR!
            rmdir /s /q "!TEMP_DIR!"
            pause
            exit /b 1
        )
    )
)

:: Clean up
echo.
echo 🧹 Cleaning up temporary files...
rmdir /s /q "!TEMP_DIR!" || (
    echo ⚠️ Warning: Failed to clean up temp directory: !TEMP_DIR!
)

echo.
echo ✅ Fat JAR created at: !OUTPUT_JAR!
echo Testing fat JAR...
java -jar "!OUTPUT_JAR!" || (
    echo ⚠️ Warning: Failed to run fat JAR. Please verify the main class or dependencies.
)

pause
exit /b 0