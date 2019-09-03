# Adding New Scripts

- Fork this repository and create pull requests to add new scripts

## Repo Structure
```
| src 
  |--windows :  Windows scripts are placed here
    |--common
      |--helpers : Windows helper scripts are placed here
      |--setup : Directory for Windows initialization scripts (init.ps1)
  |--linux : Linux scripts are placed here
    |--common
      |--helpers : Linux helper scripts are placed here
      |--setup : Directory for Linux initialization scripts (init.sh)
```

## Example Scripts
- Windows: https://github.com/Azure/repair-script-library/blob/master/src/windows/win-hello-world.ps1
- Linux: https://github.com/Azure/repair-script-library/blob/master/src/linux/linux-hello-world.sh

## Basic Guidelines
### Script Return
- A script should return/exit $STATUS_SUCCESS or $STATUS_ERROR depending on its status. These return variables are initialized within the init file located in the common/setup/ directory.

### Script Logging
- Any output or logging should be done using the functions within logger.ps1/logger.sh.
- A logger script is placed within the common/helpers directory. Importing the init file will automatically import the logger script. The logger script has logging functions which appends string to each log to label the log level and datetime. The logs are written to stdout which are redirected to file when used with the CLI vm-repair extension.
```
Log functions:
1) Log-Output
2) Log-Info
3) Log-Warning
4) Log-Error
5) Log-Debug
```
- Output logs will be shown to the user when the script is called through the CLI vm-repair extension with the 'vm repair run' command.

# How to test on CLI before merging
- There is a way to test local scripts with the CLI 'vm repair run' command
```
# Run directly on the VM
az vm repair run -g MyResourceGroup -n MySourceWinVM --custom-run-file /folder/file.ps1 --verbose
# Run on linked repair VM
az vm repair run -g MyResourceGroup -n MyWinVM --custom-run-file /folder/file.ps1 --run-on-repair --verbose
```
- Note that <b>parameter passing does not work</b> for local testing yet and script will throw error if done so.

# Contact
- caiddev@microsoft.com
