# Repair Script Library

The Repair Script Library organizes and archives known Windows and Linux repair scripts to automate frequent fix scenarios.
Each repair script has a unique ID mapped on [map.json](https://github.com/Azure/repair-script-library/blob/master/map.json)

# Run Scripts on Azure VM via Azure CLI

1. Open [Azure Cloud Shell](https://docs.microsoft.com/en-us/azure/cloud-shell/overview) (Or [install Azure CLI manually](https://docs.microsoft.com/en-us/cli/azure/install-azure-cli?view=azure-cli-latest))

[![](https://shell.azure.com/images/launchcloudshell.png "Launch Azure Cloud Shell")](https://shell.azure.com)

2. Install the vm-repair extension
```
az extension add -n vm-repair
```

3. Run a script using its unique ID mapped on [map.json](https://github.com/Azure/repair-script-library/blob/master/map.json)
```
az vm repair run -g MyResourceGroup -n MyVM --run-id win-hello-world --verbose
```

## When the VM is not bootable

1. Create a repair VM to host the fix for a source VM's OS disk
```
az vm repair create -g MyResourceGroup -n MySourceVM --verbose
```

2. Run a script on the repair VM to fix the attached source VM's OS disk (Don't forget the --run-on-repair parameter)
```
az vm repair run -g MyResourceGroup -n MyVM --run-id win-hello-world --run-on-repair --verbose
```

3. Restore the fixed OS disk onto the source VM
```
az vm repair restore -g MyResourceGroup -n MySourceVM --verbose
```

## Documentations
- [Reference Documentation](https://docs.microsoft.com/en-us/cli/azure/ext/vm-repair/vm/repair?view=azure-cli-latest)
- Run command with -h parameter to view help texts
```
az vm repair -h
az vm repair <command> -h
```

# Contributing

**Adding new scripts**: https://github.com/Azure/repair-script-library/blob/master/doc/adding_new_scripts.md

**Contact**: VMRepairDev@service.microsoft.com

This project welcomes contributions and suggestions.  Most contributions require you to agree to a
Contributor License Agreement (CLA) declaring that you have the right to, and actually do, grant us
the rights to use your contribution. For details, visit https://cla.microsoft.com.

When you submit a pull request, a CLA-bot will automatically determine whether you need to provide
a CLA and decorate the PR appropriately (e.g., label, comment). Simply follow the instructions
provided by the bot. You will only need to do this once across all repos using our CLA.

This project has adopted the [Microsoft Open Source Code of Conduct](https://opensource.microsoft.com/codeofconduct/).
For more information see the [Code of Conduct FAQ](https://opensource.microsoft.com/codeofconduct/faq/) or
contact [opencode@microsoft.com](mailto:opencode@microsoft.com) with any additional questions or comments.
