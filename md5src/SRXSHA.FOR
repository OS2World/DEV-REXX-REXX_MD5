
c$define INCL_REXXSAA
c$include rexxsaa.fap

! Declare our exported function.  Export it!

c$pragma aux (RexxFunctionHandler) SRX_SHA "SRX_SHA"

! SRX_SHA -- Returns SHA digest of a string


c$noreference
	integer function SRX_SHA( name, numargs, args,
     &                            queuename, retstr )
c$reference
	character*(*) name, queuename
	integer numargs
	record /RXSTRING/ retstr, args(numargs)
	
	include 'rxsutils.fi'
	
	integer memstat, len
	character*(*) tmp, arg1

        character *44 asrx_sha,a44


	! Make sure we have only one argument, and that it's not a
	! null string...

	if( numargs .lt. 1 )then
	    SRX_sha = 443
	    return
	endif
	if( args(1).strptr .eq. 0 .or. args(1).strlength .eq. 0 )then
 	    SRX_sha = 444
	    return
        endif

	allocate( arg1*args(1).strlength, location=args(1).strptr )

	! Get some buffer space....
	
	len = 44
	allocate( tmp*len, stat=memstat )
	if( memstat .ne. 0 )then
	    SRX_sha = 445
	    return
	endif
        
         a44=asrx_sha(arg1)

c	! Return the name of the func and the argument
c        write(tmp,881)name(1:strlen(name)),arg1,a44
c 881    format(' srx_sha as ',a,' with ',a,'=='a)
        
        tmp=a44
	call CopyResult( tmp, lentrim( tmp ), retstr )
	deallocate( tmp )
	
	SRX_sha = VALID_ROUTINE
	
	end




c --------------------
c aSRX_sha should be declared as *44 (at least)
c astring can be any length

        character *(*) function asrx_sha(astring)

        character *(*) astring

        integer addme,lenorig,lenorig8,decode4,fsha

        integer *1 pads(64)
        data pads/'80'x,63*'00'x/

        integer *1 i1a(4)               !use this for working with 
        integer  i4a
        equivalence (i4a,i1a)

        integer mess16(16)                 !16 word chunk to digest
        integer *1 mess64(64)

        equivalence(mess16,mess64)

        integer w(0:79)

        integer inn,ii,temp

        character *44 ans
        integer leftover,addbytes
        integer h0,h1,h2,h3,h4,wt2,a,b,c,d,e
        integer k,i16,i1,len2,len3,j

c         character *1 a1lc(6)
c         data a1lc/'a','b','c','d','e','f'/

        integer ks(0:79)
        data ks/20*z5a827999,20*z6ed9eba1,20*z8f1bbcdc,20*zca62c1d6/


c starting values
        h0='67452301'x
        h1='efcdab89'x
        h2='98badcfe'x
        h3='10325476'x
        h4='c3d2e1f0'x

        lenorig=len(astring)
        lenorig8=8*lenorig

        
        leftover=mod(lenorig8,512)
c pad message to multiple of 512 bits. 
c Last 2 words are 64 bit # bits in message
        if (leftover.eq.448) addme=512
        if (leftover.lt.448) addme=448-leftover
        if (leftover.gt.448) addme=960-leftover
        addBYTES=addme/8

       len2=lenorig+ADDBYTES
       len3=len2+8                     ! FINAL LENGTH IN BYTES, must be multiple of 64

c  loop through entire message -- 16 words at a time   
      inn=(len3/64)-1
      do i1 = 0,inn

          i16=i1*64
          do j=1,64
             k=i16+j    !add this byte 

C add byte from message, padding, or length 
             if (k.le.lenorig) then
                 mess64(j)=ichar(astring(k:k))
             else
                if (k.le.len2) then
                    mess64(j)=pads(k-lenorig)
                ENDIF
             ENDIF
          ENDDO                 !64 BYTES OF BLOCK
          if (i1.eq.inn) then 
                mess16(15)=0
                mess16(16)=decode4(lenorig8)
          endif


c reverse bytes in each word (sha assumes high end ordering
    
          do k=1, 16
             mess16(k)=decode4(mess16(k))
          enddo


c transform this block
c   start with compute w(0..79)
   
         do ii=0,15                       ! 0 to 15
            w(ii)=mess16(ii+1)
c                 write(6,75)ii,w(ii) ,w(ii)
c   75           format(' w ii',i6,1x,i14,1x,z10)
         enddo
         do ii=16,79
             wt2=ieor(w(ii-3),w(ii-8))
             wt2=ieor(wt2,w(ii-14))
             wt2=ieor(wt2,w(ii-16))
             w(ii)=ishc(wt2,1)
c             write(6,75)ii,w(ii) ,w(ii)
         enddo

         a=h0                     !will add them back (below)
         b=h1
         c=h2
         d=h3
         e=h4

c for w=0--79; compute hi
         do ii=0,79
            temp=ishc(a,5)+fsha(ii,b,c,d)+e+w(ii)+ks(ii)
            e=d
            d=c
            c=ishc(b,30)
            b=a
            a=temp
c        write(6,'(i8,5z10)')ii,a,b,c,d,e


         enddo

c  add back in prior values
         h0=h0+a
         h1=h1+b
         h2=h2+c
         h3=h3+d
         h4=h4+e

      enddo                       !16 word block

      write(ans,'(z8,1x,z8,1x,z8,1x,z8,1x,z8)')h0,h1,h2,h3,h4


c convert to lower case
c      do il=1, 44
c         icc=index('ABCDEF',ANS(IL:il))
c           if (icc.gt.0) ans(il:il)=a1lc(icc)
c      enddo

      asrx_sha=ans
      return
      end




c*********** Basic function */
c fsha(t,b,c,d; 0 <= t <=19 ) == (b and c) or ( (not b) and D )
c             20<= t <= 39  == b xor c xor d
c             40<=t<=59     == (b and c) or (b and d) or (c and d)
c             60<=t<=79     == b xor c xor d
             

        INTEGER FUNCTION fsha(t,b,c,d)
         integer t,b,c,d
         integer t1,t2,t3

         select case(t)
         case (0:19)
             t1=iand(b,c)
             t2=iand(not(b),d)
             fsha=ior(t1,t2)
         case (20:39)
             t1=ieor(b,c)
             fsha=ieor(t1,d)
         case (40:59)
             t1=iand(B,c)
             t2=iand(b,d)
             t3=iand(c,d)
             t1=ior(t1,t2)
             fsha=ior(t1,t3)
         case (60:79)
             t1=ieor(b,c)
             fsha=ieor(t1,d)
         otherwise
            print *,' sha case error ',t
            stop                /* error */
         end select

         return

        end

c -------- reverse byte order in an integer
        integer function decode4(ido)
        integer ido,itmp,itmpb,i
        integer *1 itmp1(4),itmp2(4)
        equivalence(itmp,itmp1)
        equivalence(itmpb,itmp2)
        itmp=ido
        do i=1,4
          itmp2(i)=itmp1(5-i)
        enddo
        decode4=itmpb
        return
        end


