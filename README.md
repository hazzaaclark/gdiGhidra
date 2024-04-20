# gdiGhidra
SEGA Dreamcast GDI parsing tool for GHIDRA

# The motive:

The motive behind this project is to create a reverse-engineering toolkit for the NSA's [Ghidra](https://github.com/NationalSecurityAgency/ghidra)
to allow me to parse contents from the SEGA Dreamcast's prepriatory file type called GDI (or GDRom).

The toolkit will allow emulated talk between the decompiler and the Binary of the GDi file to be able to decompile to the lowest form factor.
Whereby that Binary has been converted to ASM of the decompiler's reccomendation (typically Intel 8086)

# Buidling:

- Ensure you have the latest version of the Java [JDK](https://www.oracle.com/java/technologies/javase/jdk17-archive-downloads.html)
- Setup your ``GHIDRA_INSTALL_DIR`` to the corresponding location on your PC; the easiest way to do this is by adding ``GHIDRA_INSTALL_DIR`` to
your Windows Environment Variables.

- Run ``./gradlew.bat``
- The final output will be in a seperate folder called ``/dist``

- Copy the zip file to `/GHIDRA_INSTALL_DIR/Extensions/Ghidra`
- Start Ghidra and use the "Install Extensions" dialog to finish the installation. (File -> Install Extensions...).

# Sources:

[Ghidra](https://github.com/NationalSecurityAgency/ghidra)

[Hitachi Super 4 CPU](https://retrocdn.net/images/6/61/SH-4_32-bit_CPU_Core_Architecture.pdf)
