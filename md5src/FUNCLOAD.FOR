! funcload.for -- Defines the two functions 'SRXLoadFuncs' and 'SRXDropFuncs',
!                 which load/drop all the functions defined in this DLL.

c$define INCL_REXXSAA
c$include rexxsaa.fap

! Declare our functions.  Make sure to export these in the .LNK file!

c$pragma aux (RexxFunctionHandler) SRXLoadFuncs "SRXLoadFuncs"
c$pragma aux (RexxFunctionHandler) SRXDropFuncs "SRXDropFuncs"

! Define the table that lists REXX function names and the corresponding
! DLL entry point.  You must change this table whenever you add/remove
! a function or entry point.

	blockdata
	include 'funcload.fi'
	data RxFncTable/
		! function	entry point
     &		'SRXLoadFuncs'c,  'SRXLoadFuncs'c,
     &		'SRXDropFuncs'c,  'SRXDropFuncs'c,
     &		'SRX_MD4'c,      'SRX_MD4'c,
     &		'SRX_ROLL32'c,       'SRX_ROLL32'c,
     &		'SRX_MD5'c,      'SRX_MD5'c,
     &		'SRX_COUNT_CHARS'c,      'SRX_COUNT_CHARS'c,
     &		'SRX_SHA'c,      'SRX_SHA'c/
	end

! SRXLoadFuncs -- Register all the functions with REXX.

c$noreference
	integer function SRXLoadFuncs( name, numargs, args,
     &				      queuename, retstr )
c$reference
	integer numargs, name, queuename
	record /RXSTRING/ args(numargs), retstr
	
	include 'rxsutils.fi'
	include 'funcload.fi'
	
    	integer j
	character*9 DLLNAME ! Change this if you're changing the DLL name...
	parameter (DLLNAME = 'SRXFUNC'c)
	
	retstr.strlength = 0

	if( numargs .gt. 0 )then
	    SRXLoadFuncs = INVALID_ROUTINE
	    return
	endif

	do j = 1, ENTRIES
	    call RexxRegisterFunctionDll( RxFncTable(j).rxName, DLLNAME,
     &					  RxFncTable(j).cName )
	enddo

	SRXLoadFuncs = VALID_ROUTINE

	end

* SRXDropFuncs -- Deregister all the functions with REXX.

c$noreference
	integer function SRXDropFuncs( name, numargs, args,
     &				      queuename, retstr )
c$reference
	integer numargs, name, queuename
	record /RXSTRING/ args(numargs), retstr
	
	include 'rxsutils.fi'
	include 'funcload.fi'
	
	integer j

	retstr.strlength = 0

	if( numargs .gt. 0 )then
	    SRXDropFuncs = INVALID_ROUTINE
	    return
	endif

	do j = 1, ENTRIES
	    call RexxDeregisterFunction( RxFncTable(j).rxName )
	enddo

	SRXDropFuncs = VALID_ROUTINE

	end
