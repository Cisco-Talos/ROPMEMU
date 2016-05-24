### ROPMEMU

ROPMEMU is a framework to analyze, dissect and decompile complex 
code-reuse attacks. It adopts a set of different techniques to analyze 
ROP chains and reconstruct their equivalent code in a form that can be 
analyzed by traditional reverse engineering tools. In particular, 
it is based on memory forensics (as its input is a physical memory dump), 
code emulation (to faithfully rebuild the original ROP chain), multi-path 
execution (to extract the ROP chain payload), CFG recovery (to rebuild 
the original control flow), and a number of compiler transformations 
(to simplify the final instructions of the ROP chain).

Specifically, the memory forensics part is based on Volatility [1] plugins.
The emulation and the multi-path part is implemented through the Unicorn 
emulator [2].

ROPMEMU has been published at AsiaCCS 2016 [3] and the paper can be found here [4].

ROPMEMU documentation can be found in the [Wiki pages](https://github.com/vrtadmin/ROPMEMU/wiki).

Happy hacking!

- [1] http://www.volatilityfoundation.org/#!23/c173h
- [2] http://www.unicorn-engine.org/
- [3] http://meeting.xidian.edu.cn/conference/AsiaCCS2016/home.html
- [4] http://s3.eurecom.fr/docs/asiaccs16_graziano.pdf
