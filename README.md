# blockchain21
A very simple bitcoin blockchain parser


To build for Linux use the provided Makefile

To build for Visual Studio go to the directory: ./compiler/xpj

The windows executable is called:

blockchain21.exe

Command line options are:

-max_blocks <n>  : Sets the maximum number of blocks in the blockchain to scan for.  Default is the entire blockchain.
-text <n>		 : Specifies how many bytes of ASCII text to consider before reporting contents to AsciiTextReport.txt

Example usage to scan the blockchain for the first 200 blocks, output any ASCII text found greater than or equal to 16 bytes
in length and display the block contents.

blockchain21 -max_blocks 200 -text 16 c:\bitcoin\blocks

