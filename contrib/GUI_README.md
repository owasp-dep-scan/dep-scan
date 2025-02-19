## Enabling GUI mode for dep-scan

dep-scan can be run in GUI mode by passing the `--gui` or `-g` flag to the command line. This will open a new window with the GUI and show the available input options.


The code to enable the GUI is present at: https://github.com/saketjajoo/dep-scan/commit/27c397bb551ada79bfc344d39399a896ecd38cef.

> [!NOTE]
> This is a work in progress as this can be a breaking change. Hence, this is not merged into the master branch yet.

PR to introduce the GUI mode: https://github.com/owasp-dep-scan/dep-scan/pull/179

The GUI mode is introduced via the [Gooey Python library](https://pypi.org/project/Gooey/) which, [under the hood](https://github.com/chriskiehl/Gooey/blob/master/setup.py#L18), uses the [wxPython library](https://wxpython.org/) to create the GUI. The wxPython library has 2 core requirements:
- Python version must be >= 3.7.0
- [gtk-3.0+ package must be installed for the Linux-based machines](https://wxpython.org/blog/2017-08-17-builds-for-linux-with-pip/index.html) (`sudo apt-get install build-essential libgtk-3-dev`)

wxPython uses the underlying host OS's architecture to build the GUI. Thus, this feature may require additional steps than just simply installing Gooey via pip as the installation is host OS architecture dependent. This means that if this change is introduced in dep-scan, the builds will need to be OS architecture based. Hence, this feature can be a breaking change and it is yet to figured out how to introduce this in the dep-scan environment.

### Example GUI
![dep-scan GUI](dep-scan-gui.png)
