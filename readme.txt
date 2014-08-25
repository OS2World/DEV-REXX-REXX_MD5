9 April 2000. Daniel Hellerstein, danielh@crosslink.net

                REXX tools for computing MD4 and MD5 digests 

Description:

 REXX_MD5 contains several OS/2 REXX tools that allow you to compute
 the MD4 and MD5 digests of any string.

     1) REXX_MD5) An "all rexx code" procedure
                  For example: MyMD5=rexx_md5('a string to digest')

              Since REXX is weak at repetitive math, this
              method (REXX_MD5) is not very fast (actually, it's 
              excuriatingly slow on large strings). For smaller 
              strings (say, less then a few hundred characters) it's 
              tolerable. 

     2) REXX_MD4) An "all rexx code" procedure
                  For example: MyMD4=rexx_md4('a string to digest')

              Since REXX is weak at repetitive math, this
              method (REXX_MD4) is not very fast (actually, it's 
              excuriatingly slow on large strings). For smaller 
              strings (say, less then a few hundred characters) it's 
              tolerable. 


     2) SRXFUNC) A DLL containing SRX_MD4 and SRX_MD5 (and other procedures)  
                 Examples: MyMD5=srx_md5('a string to digest')       
                           MyMD4=srx_md4('a string to digest')       

              For longer strings, these functions (contained in
              the SRXFUNC.DLL) are recommended over the REXX_MD4 and
              REXX_MD5 functions -- they are much faster, and just as 
              easily called. 

              Note that SRX_MD5 can also be called "sequentially", so
              as to build the MD5 of a large string (or file) from
              it's constituent pieces. See MD5_FILE.CMD, and SRXFUNC.DOC,
              for the details.

              A description of all the SRXFUNC procedure can be 
              found in SRXFUNC.DOC.

      The only drawback to using SRX_MD4 and SRX_MD5 is that you have to
      distribute the DLL as a seperate file; whereas REXX_MD5 can be included
      in your REXX source code.

 

MD5 digests of files:

     A simple, but quick, "MD5 of a file" program is provided (MD5_FILE.CMD)
       
     As an alternative, you might find the MD5.EXE at 
          http://hobbes.nmsu.edu/pub/os2/unix/apps/misc/md5_os2.zip 
     to be convenient (it's a standalone program).
                          

Examples:

  The TESTMD5.CMD and TESTMD4.CMD programs demonstrate the use of both 
  tools (and shows how to load the SRX_MD4 and SRX_MD5 procedures
  from SRXMD5.DLL).

  MD5_FILE.CMD shows how SRX_MD5 can be used to "sequentially" compute
  the MD5 of an arbitrarily long file.


Source Code:
     
   MD5SRC.ZIP contains the source code used to create SRXMD5.DLL.  It's
   written in Fortran (WATCOM 11.0b).  You can use WMAKE (with the 
   included MAKEFILE), to recreate SRXFUNC.DLL (be sure that the
   FINCLUDE environment variable points to a directory containing
   the several REXXSAA.* files).


Conditions of Use:

   The programs contained herein may be freely used by anyone for any purpose.
   You may include this product in your own work and distribute it freely,
   with the understanding that recipients of this product have the same
   rights. Proper attribution is expected, but need not be prominent.

Disclaimer:
  
   We, the authors of REXX_MD5 and any potentially affiliated institutions,
   disclaim any and all liability for damages due to the use, misuse, or
   failure of the product or subsets of the product. Use it at your
   own risk!  That said: the product has been tested, and is used in other
   work of ours (but please do note the above caution). If you should find a 
   problem, PLEASE LET US KNOW (see the address at the top of this document).


   
Bonus: Also contains srx_sha: SHA-1 digest.

