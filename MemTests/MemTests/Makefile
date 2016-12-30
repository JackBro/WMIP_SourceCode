# Makefile for MemTests.exe
# =========================


# ----------------------------------------------------------------------

# Includes
# --------

# *** Win32.mak inclusion ***

!include <Win32.mak>


# ----------------------------------------------------------------------

# Environment-dependent macros
# ----------------------------

!IFDEF NODEBUG

!ERROR Only debug build supported

!ELSE

TARG_PATH = Debug
MY_COMPIL_OPTS = /FAs /Fa"$(TARG_PATH)\\" /EHac- /Fp"$(TARG_PATH)\\"  \
	/Fo"$(TARG_PATH)\\" /Fd"$(TARG_PATH)\\"

LINK_OPTS_EXE = $(ldebug) $(conlflags) $(conlibsdll)  /MAP:$*.map /MAPINFO:EXPORTS -out:$@
!ENDIF

# ----------------------------------------------------------------------

# Project Specific Macros
# -----------------------

PROJ = MemTests
PROJ_OBJS  = $(TARG_PATH)\main.obj 
PROJ_COMPIL_OPTS = $(cdebug) $(cflags) $(cvarsmt) $(MY_COMPIL_OPTS) /DUNICODE /D_UNICODE /I..\KrnlAllocs


# ----------------------------------------------------------------------
#
# Targets
# -------

all: $(TARG_PATH) $(TARG_PATH)\$(PROJ).exe 



# If TARG_PATH does not exist, then create directory
#
$(TARG_PATH) :
    if not exist "$(TARG_PATH)/$(NULL)" mkdir $(TARG_PATH)

$(TARG_PATH)\main.obj: main.cpp ..\KrnlAllocs\KaDrvR3.H


# Build rule for $(PROJ).exe
#
$(TARG_PATH)\$(PROJ).EXE: $(PROJ_OBJS) 
	$(link) $(LINK_OPTS_EXE) $(PROJ_OBJS) 


# ----------------------------------------------------------------------
#
# Inference rules
# ---------------
.SUFFIXES :
.SUFFIXES : .obj .cpp


{.}.cpp{$(TARG_PATH)}.obj:
	$(cc) $(PROJ_COMPIL_OPTS) $(@B).cpp
	
