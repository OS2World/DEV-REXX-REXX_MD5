/* */
parse arg foo1
if foo1='' | foo1='?'then do 
  say "Program to compute the MD5 of a file, or of a directory"
  say "Examples: "
  say "  x:>md5_file d:\os2\attrib.exe"
  say "  x:>md5_file d:\os2\bin\*.*"
  exit
end /* do */


/* Load up advanced REXX functions */
foo=rxfuncquery('sysloadfuncs')
if foo=1 then do
  call RxFuncAdd 'SysLoadFuncs', 'RexxUtil', 'SysLoadFuncs'
  call SysLoadFuncs
end

oy=sysfiletree(foo1,'oy1','FO')
do mm=1 to oy1.0
   ii=stream(oy1.mm,'c','query size')
   hh2=seq_md5_file(oy1.mm)
   say  hh2  oy1.mm 
end

exit


seq_md5_file:procedure 

   parse arg afile              /* foo1 is the string to be md5'ized */

   nbytes=stream(afile,'c','query size')
   if nbytes='' | nbytes=0 then return ' '

   foo=stream(afile,'c','open read')
   if abbrev(translate(strip(foo)),'READY:')=0 then return ' '

   gobble=64*500              /* 32k pieces -- any multiple of 64 is okay*/

   if nbytes<= gobble then do   /* small string? do it all at once */
       BOB=charin(afile,1,nbytes)
       foo=stream(afile,'c','close')
       md5=srx_md5(BOB)              
       return md5
   end                 /* else, do it in pieces */

   p1=charin(afile,1,gobble)       /* get first piece */

  stuff=srx_md5(p1,0)            /* stuff contains A B C D components of md5 */
  if abbrev(stuff,'error_')=1 then do
        say stuff
        exit
  end 

   iat=gobble+1  
   iat2=iat+gobble-1   
   do while iat2 <= nbytes        /* do  "intermediate" pieces */
      p1=charin(AFILE,,gobble)
      stuff=srx_md5(p1,0,stuff)        /* note recursive use of STUFF */
      if abbrev(stuff,'error_')=1 then do
          say stuff
          exit
     end 
      iat=iat+gobble
      iat2=iat+gobble-1   


   end
   p1=charin(AFILE,,1+NBYTES-IAT)
    foo=stream(afile,'c','close')
   md5=srx_md5(p1,1,stuff)      /* and compute md5 -- 1 signals "last piece" */

   return md5


