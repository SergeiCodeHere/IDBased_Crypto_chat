from cx_Freeze import setup, Executable

base = None

executables = [Executable("run_client.py", base=base)]

packages = ["idna", "PyQt5", 'IBСCrypto']
options = {
    'build_exe': {
        'packages': packages,
    },
}

setup(
    name="Client",
    options=options,
    version='1.0.0.0',
    description='<1>',
    executables=executables
)
