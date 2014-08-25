c count number of occurences of characters (0-255)
c input is a filename. Or, if two arguments, input is a string
c output is a crlf delimited list of 256 entries, each line of
c which is the # of instances of that character found in the file


c$define INCL_REXXSAA
c$include rexxsaa.fap

! Declare our exported function.  Export it!

c$pragma aux (RexxFunctionHandler) SRX_COUNT_CHARS "SRX_COUNT_CHARS"

! SRX_COUNT_CHARS -- count occurences of all 0-255 ascii characters in a file

c$noreference
	integer function SRX_COUNT_CHARS( name, numargs, args,
     &                            queuename, retstr )
c$reference
	character*(*) name, queuename
	integer numargs
	record /RXSTRING/ retstr, args(numargs)


        integer *1 aa(1000),aa2
        integer cts(0:255)
        
	include 'rxsutils.fi'

        integer iread,mm
	integer memstat, klen,il,nn,iaa,jj
	character*(*) tmp, arg1

	if( numargs .lt. 1.or.numargs.gt.2 )then
	    SRX_COUNT_CHARS = 443
           deallocate( tmp )
           deallocate(arg1)
	    return
	endif
	
	allocate( arg1*args(1).strlength, location=args(1).strptr )


	! Get some buffer space....
	
	klen = 256*8
	allocate( tmp*klen, stat=memstat )
	if( memstat .ne. 0 ) then
	    SRX_COUNT_CHARS = 445
            deallocate( tmp )
            deallocate(arg1)
	    return
	endif

        do mm=0,255     !avoid static problems
          cts(mm)=0
        enddo

c if 2nd arg, any 2nd arg, then first arg is a string.
        if (numargs.eq.2) then 
           do mm=1,len(arg1)
              aa2=ichar(arg1(mm:mm))
              iaa=aa2
              if (iaa.lt.0)iaa=256+iaa
              cts(iaa)=cts(iaa)+1
           enddo
           goto 900
        endif
       
c else, read a file (1000 bytes at a time)

        open(unit=21,file=arg1,form='unformatted',
     1           access='direct',recl=1000,err=1410)


        iread=0
        do mm=1,1000000
          read(21,rec=mm,err=1410,end=20)(aa(il),il=1,1000)
          do nn=1,1000
           iaa=aa(nn)
           if (iaa.lt.0)iaa=256+iaa
           cts(iaa)=cts(iaa)+1
           iread=iread+1
          enddo
        enddo

 20     continue                !here at eof by 1000

        close(unit=21)
        open(unit=21,file=arg1,form='unformatted',
     1           access='direct',recl=1)
        jj=iread+1
        do mm=jj,1234567890
           read(21,rec=mm,err=1410,end=22)aa2
           iaa=aa2
           if (iaa.lt.0)iaa=256+iaa
           cts(iaa)=cts(iaa)+1
           iread=iread+1
        enddo
 22     continue                ! here at real eof
        close(unit=21)

c        print *,' rad ',iread
 900    continue
       write(tmp,91)(cts(jj),jj=0,255)
 91     format(256(z8))

c return results/
 1000       call CopyResult( tmp, lentrim( tmp ), retstr )
       deallocate( tmp )
       deallocate(arg1)

       SRX_COUNT_CHARS = VALID_ROUTINE
       return


1410   TMP='file read error' 
        call CopyResult(TMP, lentrim(TMP), retstr )
       deallocate( tmp )
       deallocate(arg1)
       SRX_COUNT_CHARS = 4462
       return

        end

