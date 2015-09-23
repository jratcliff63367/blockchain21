@echo off

set XPJ="xpj4.exe"

%XPJ% -v 1 -t VC11 -p WIN64 -x blockchain21.xpj
%XPJ% -v 1 -t VC12 -p WIN64 -x blockchain21.xpj

cd ..
@rem cd vc11win64
cd vc12win64

goto cleanExit

:pauseExit
pause

:cleanExit

