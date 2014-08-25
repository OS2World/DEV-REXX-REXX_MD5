c Compute adler-32 style rolling checksum . 
c Call as:
c  csum=SRX_ROLL32(message)
c    Where:
c        message: a character string (any size)
c        csum: contains 3 space delimited words:
c               the checksum (as a 8char hex value), 
c               alpha and beta (as 5 digit integers)
c    
c     Example: SRX_ROLL32("This is a message:",18,"")
c             yields 3BB90654
c
c  Alternatively
c
c  csum=SRX_ROLL32(message,addstuff)
c    Where:
c        message: a character string (any size)
c        addstuff: a character string to add, 1 at a time
c        csum: contains  len(addstuff) checksums, in a concatenated
c              string, w/each checksum a 4byte character
c               the 1 ... len(addstuff)+1 contain "rolling" checksums
c               built from addstuff. 
c               Thus:the 3rd checksum in csum is computed using
c                     message(3:len(message)) + addstuff(1:2)
c              (if len(addstuff)>len(message), use earlier parts of addstuff
c         Thus, csum will be len(addstuff)*4 long
c     Example: 
c       SRX_ROLL32("This is a message:","Hey")
c


c$define INCL_REXXSAA
c$include rexxsaa.fap

! Declare our exported function.  Export it!

c$pragma aux (RexxFunctionHandler) SRX_ROLL32 "SRX_ROLL32"

! srx_roll32 -- Returns a rolling checksum of a string


c$noreference
	integer function SRX_ROLL32( name, numargs, args,
     &                            queuename, retstr )
c$reference
	character*(*) name, queuename
	integer numargs
	record /RXSTRING/ retstr, args(numargs)
	
	include 'rxsutils.fi'
	
	integer memstat
	character*(*) tmp, arg1,arg2

        integer chksum,ialpha,ibeta,klen
        integer alpha,beta,k1,ikk,ic1,ic1old,chksnew
        character *4 cbuf4
        integer len_arg1,len_arg2
        integer igoo4
        character *4 goo4
        equivalence (igoo4,goo4)

c at least one argument
	if( numargs .gt. 2 .or. numargs.eq.0) then
	    SRX_ROLL32 = 443
	    return
	endif

	allocate( arg1*args(1).strlength, location=args(1).strptr )
        len_arg1=len(arg1)
        klen=20

        if (numargs.eq.2) then
            allocate( arg2*args(2).strlength, location=args(2).strptr )
            len_arg2=len(arg2)
            klen=(1+len_arg2)*4
         endif
        
	! Get some buffer space for result ....
	allocate( tmp*klen, stat=memstat )
	if( memstat .ne. 0 )then
	    SRX_ROLL32 = 445
	    return
	endif

         ialpha=alpha(arg1,len_arg1)
         ibeta=beta(arg1,len_arg1)           
         chksum=ialpha +  (65536*ibeta)

        if (numargs.eq.1) then 
           write(tmp,883,err=1410)chksum
           goto 1000            ! all done, return results
        endif

 883    format(z8)

c or additional checksums 

       igoo4=chksum
       write(cbuf4,881)goo4
       tmp(1:4)=cbuf4

        k1=1
        do ikk=1,len_arg2
            ic1=ichar(arg2(ikk:ikk))
            if (ikk.le.len_arg1) then 
               ic1old=ichar(arg1(ikk:ikk))
            else
               ic1old=ichar(arg2(ikk-len_arg1:ikk-len_arg1))
            endif

            ialpha=ialpha-ic1old+ic1
            if (ialpha .lt.0) then 
               ialpha=65536+ialpha
            endif

            ibeta=ibeta+ialpha-(len_arg1*ic1old)
            ibeta=mod(ibeta,65536)
            if (ibeta .lt.0) then 
               ibeta=65536+ibeta
            endif
            chksnew=ialpha +  (65536*ibeta)
            k1=k1+4
            igoo4=chksnew
            write(cbuf4,881)goo4
            tmp(k1:k1+3)=cbuf4
        enddo
 881    format(a4)

        deallocate(arg2)        ! and then return results ...

c return results
 1000       call CopyResult( tmp, lentrim( tmp ), retstr )
       deallocate( tmp )
       deallocate(arg1)
       SRX_ROLL32 = VALID_ROUTINE
       return

1410   TMP='read/write error' 
        call CopyResult(TMP, lentrim(TMP), retstr )
       deallocate( tmp )
       deallocate(arg1)
       SRX_ROLL32 = 4462
       return


        END

c *****
c compute alpha component 
        integer function alpha(astring,ilen)
        
        character *(*)astring
        integer ilen,i1,i2,isum

        isum=0

        do i1=1,ilen
          i2=ichar(astring(i1:i1))
          isum=isum+i2
        enddo 
        isum=mod(isum,65536)
        if (isum.lt.0)isum=isum+65536
        alpha=isum
        return 
        end

c **************
c compute beta component */
        integer function beta(astring,ilen)
        
        character *(*)astring
        integer ilen,i1,i2,isum

        isum=0
        do i1=1,ilen
          i2=ichar(astring(i1:i1))
          isum=((ilen-i1+1)*i2) + isum
        enddo 
        isum=mod(isum,65536)
        if (isum.lt.0)isum=isum+65536
        beta=isum
        
        return
        end

