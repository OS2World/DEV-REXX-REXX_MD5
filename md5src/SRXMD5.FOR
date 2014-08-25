c MD5 creation. Sequential MD5 also supported.
c 1,2, or 3 arguments:
c  1 argument: compute and return md5 of arg1
c  2 arguments:  
c     if arg2=0
c         compute md5 of arg1, return  A B C D LENBITS
c     if arg2=1
c          same as 1 argument mode (return md5 of arg1)
c                parameters.
c     3 arguments: 
c      if arg2 =0
c          augment md5 with contents of arg1, using arg3 as starting
c          A B C D LENBITS values
c      if arg2 =1
c          return MD5 of arg1, using arg3 as starting values.
c  Basically, the one argument mode is used for short strings,
c  or for mid-length strings in single threaded enviroments.
c  For longer strings in multi-threaded environments, the use
c  of sequential calls avoids some problems (that can cause
c  sys3175 errors)
c
c Returns:
c   MD5, if no second arg, or 2nd arg=1
c   A B C D LENBITS registers (in 5(z8) format)
c   error_message if an error occured  (only possible if > 1 argument)
c
c

c      
c$define INCL_REXXSAA
c$include rexxsaa.fap

! Declare our exported function.  Export it!

c$pragma aux (RexxFunctionHandler) SRX_MD5 "SRX_MD5"

! SRX_MD5 -- Returns md5 digest of a string


c$noreference
	integer function SRX_MD5( name, numargs, args,
     &                            queuename, retstr )
c$reference
	character*(*) name, queuename
	integer numargs
	record /RXSTRING/ retstr, args(numargs)
	
	include 'rxsutils.fi'
	
	character*(*)  arg1,arg2,arg3
        integer jtype

        character *40 a32,asrx_md5,oldreg

	if( numargs .lt. 1 )then               ! has to be at least 1 arg
	    SRX_MD5 = 443
	    return
	endif

c null string is special.
	if( args(1).strptr .eq. 0 .or. args(1).strlength .eq. 0 )then
            a32='d41d8cd98f00b204e9800998ecf8427e'  !null string value
            goto 2000
	endif

	allocate( arg1*args(1).strlength, location=args(1).strptr )

        jtype=1                 ! assume "non-sequential"
        if (numargs.gt.1) then 

  	   allocate( arg2*args(2).strlength, location=args(2).strptr )
           jtype=index(arg2,'1')
           if (jtype.gt.0) jtype=1
        endif

c        write(6,666)arg2,jtype
c 666    format(1x,a,' == ',i5)

        oldreg=' '
        if (numargs.gt.2) then            ! get starting value of registers?
  	   allocate( arg3*args(3).strlength, location=args(3).strptr )
           oldreg=arg3
        endif

c Get some buffer space....

c        write(6,111)jtype
c 111    format(' jtype ',i6)        

       a32=asrx_md5(arg1,jtype,oldreg)

 2000   continue
	call CopyResult(a32,lentrim(a32), retstr )
	SRX_MD5 = VALID_ROUTINE
	
	end


c --------------------
c astring can be any length. Jtype=0 or 1, oldreg is '', or
c contains A B C D 

        character *(*) function asrx_md5(astring,jtype,oldreg)


        character *(*) astring,oldreg
        integer jtype
        integer addme,lenorig,lenorig8

        integer *1 pads(64)
        data pads/'80'x,63*'00'x/

        integer *1 i1a(4)               !use this for working with 
        integer  i4a
        equivalence (i4a,i1a)

        integer mess16(16),x(0:15)                 !16 word chunk to digest
        integer *1 mess64(64)
        equivalence(mess16,mess64,x)

        integer lenbits(2)              !# bits in message
        integer *1 lenbits_1(8)
        equivalence(lenbits,lenbits_1)
       
        character *40 ans
        integer leftover,addbytes
        integer a,b,c,d,aa,bb,cc,dd,il,icc,k,i16,i1,len2,len3,j

        integer s11,s12,s13,s14,s21,s22,s23,s24,s31,s32,s33,s34
        integer s41,s42,s43,s44

        integer ierr1,ixx,lenwas,lenorig8b

        character *1 a1lc(6)
        data a1lc/'a','b','c','d','e','f'/

        lenorig=len(astring)
        lenorig8=8*lenorig
      
        leftover=mod(lenorig8,512)

c sequential (intermediate or first) -- then MUST be multiple of 64 bytes long
        if (leftover.ne.0.and.jtype.eq.0) then
          asrx_md5='error_bad_size'
          return
        endif

c set register values
        if (oldreg.eq.' ') then   !only, or first, piece
           a ='67452301'x 
           b ='efcdab89'x 
           c ='98badcfe'x 
           d ='10325476'x 
           lenorig8b=lenorig8
        else
          read(oldreg,81,iostat=ierr1)a,b,c,d,lenwas
          if (Ierr1.ne.0) then
               asrx_md5='error_read_register'
               return
          endif
 81       format(5z8)
          lenorig8b=lenwas+lenorig8
        endif

        lenbits(1)=lenorig8b

c pad message to multiple of 512 bits. 
c Last 2 words are 64 bit # bits in message
        if (jtype.eq.1) then
          if (leftover.eq.448) addme=512
          if (leftover.lt.448) addme=448-leftover
          if (leftover.gt.448) addme=960-leftover
          addBYTES=addme/8
          len2=lenorig+ADDBYTES
          len3=len2+8                     ! FINAL LENGTH IN BYTES, must be multiple of 64
        else
           len3=lenorig                 !note: lenorig MUST be multiple of 64
        endif


c----------------------------
c  loop through entire message -- 16 words at a time   
       ixx=((len3/64)-1)
       do i1 = 0,ixx
          i16=i1*64
          do j=1,64
             k=i16+j    !add this byte 

C add byte from message, padding, or length 
             if (k.le.lenorig) then
                 mess64(j)=ichar(astring(k:k))
             else
                if (k.le.len2) then
                 mess64(j)=pads(k-lenorig)
                else
                  mess64(j)=lenbits_1(k-len2)
                ENDIF
             ENDIF
          ENDDO                 !64 BYTES OF BLOCK

c  transform this block of 16 chars to 4 values. Save prior values first */
        aa=a
        bb=b
        cc=c
        dd=d


c do 4 rounds, 16 operations per round (rounds differ in bit'ing functions 

        S11=7
        S12=12
        S13=17
        S14=22

          call round1(a, b, c, d, x( 0), S11, 'd76aa478'x)  ! /* 1 */
          call round1(d, a, b, c, x( 1), S12, 'e8c7b756'x) ! /* 2 */
          call round1(c, d, a, b, x( 2), S13, '242070db'x) !  /* 3 */
          call round1(b, c, d, a, x( 3), S14, 'c1bdceee'x) !  /* 4 */
          call round1(a, b, c, d, x( 4), S11, 'f57c0faf'x) !  /* 5 */
          call round1(d, a, b, c, x( 5), S12, '4787c62a'x) !  /* 6 */
          call round1(c, d, a, b, x( 6), S13, 'a8304613'x) !  /* 7 */
          call round1(b, c, d, a, x( 7), S14, 'fd469501'x) !  /* 8 */
          call round1(a, b, c, d, x( 8), S11, '698098d8'x) !  /* 9 */
          call round1(d, a, b, c, x( 9), S12, '8b44f7af'x) !  /* 10 */
          call round1(c, d, a, b, x(10), S13, 'ffff5bb1'x) !  /* 11 */
          call round1(b, c, d, a, x(11), S14, '895cd7be'x) !  /* 12 */
          call round1(a, b, c, d, x(12), S11, '6b901122'x) !  /* 13 */
          call round1(d, a, b, c, x(13), S12, 'fd987193'x) !  /* 14 */

c       write(6,773)k,a,b,c,d,x(13),x(14),x(15)
c 773    format(' rnd 1a ',i8,'==',7z12)


          call round1(c, d, a, b, x(14), S13, 'a679438e'x) !  /* 15 */
          call round1(b, c, d, a, x(15), S14, '49b40821'x) !  /* 16 */


c       write(6,771)k,a,b,c,d
c 771    format(' rnd 1 ',i8,4z10)

c /* Round 2 */
        S21=5
        S22=9
        S23=14
        S24=20

          call round2(a, b, c, d, x( 1), S21, 'f61e2562'x) !  /* 17 */
          call round2(d, a, b, c, x( 6), S22, 'c040b340'x) !  /* 18 */
          call round2(c, d, a, b, x(11), S23, '265e5a51'x) !  /* 19 */
          call round2(b, c, d, a, x( 0), S24, 'e9b6c7aa'x) !  /* 20 */
          call round2(a, b, c, d, x( 5), S21, 'd62f105d'x) !  /* 21 */
          call round2(d, a, b, c, x(10), S22,  '2441453'x) !  /* 22 */
          call round2(c, d, a, b, x(15), S23, 'd8a1e681'x) !  /* 23 */
          call round2(b, c, d, a, x( 4), S24, 'e7d3fbc8'x) !  /* 24 */
          call round2(a, b, c, d, x( 9), S21, '21e1cde6'x) !  /* 25 */
          call round2(d, a, b, c, x(14), S22, 'c33707d6'x) !  /* 26 */
          call round2(c, d, a, b, x( 3), S23, 'f4d50d87'x) !  /* 27 */
          call round2(b, c, d, a, x( 8), S24, '455a14ed'x) !  /* 28 */
          call round2(a, b, c, d, x(13), S21, 'a9e3e905'x) !  /* 29 */
          call round2(d, a, b, c, x( 2), S22, 'fcefa3f8'x) !  /* 30 */
          call round2(c, d, a, b, x( 7), S23, '676f02d9'x) !  /* 31 */
          call round2(b, c, d, a, x(12), S24, '8d2a4c8a'x)!  /* 32 */

c  /* Round 3 */
        S31= 4
        S32= 11
        S33= 16
        S34= 23

          call round3(a, b, c, d, x( 5), S31, 'fffa3942'x) !  /* 33 */
          call round3(d, a, b, c, x( 8), S32, '8771f681'x) !  /* 34 */
          call round3(c, d, a, b, x(11), S33, '6d9d6122'x) !  /* 35 */
          call round3(b, c, d, a, x(14), S34, 'fde5380c'x) !  /* 36 */
          call round3(a, b, c, d, x( 1), S31, 'a4beea44'x) !  /* 37 */
          call round3(d, a, b, c, x( 4), S32, '4bdecfa9'x) !  /* 38 */
          call round3(c, d, a, b, x( 7), S33, 'f6bb4b60'x) !  /* 39 */
          call round3(b, c, d, a, x(10), S34, 'bebfbc70'x) !  /* 40 */
          call round3(a, b, c, d, x(13), S31, '289b7ec6'x) !  /* 41 */
          call round3(d, a, b, c, x( 0), S32, 'eaa127fa'x) !  /* 42 */
          call round3(c, d, a, b, x( 3), S33, 'd4ef3085'x) !  /* 43 */
          call round3(b, c, d, a, x( 6), S34,  '4881d05'x) !  /* 44 */
          call round3(a, b, c, d, x( 9), S31, 'd9d4d039'x) !  /* 45 */
          call round3(d, a, b, c, x(12), S32, 'e6db99e5'x) !  /* 46 */
          call round3(c, d, a, b, x(15), S33, '1fa27cf8'x) !  /* 47 */
          call round3(b, c, d, a, x( 2), S34, 'c4ac5665'x) !  /* 48 */

c  /* Round 4 */
        S41=6
        S42=10
        S43=15
        s44=21

          call round4(a, b, c, d, x( 0), S41, 'f4292244'x)!  /* 49 */
          call round4(d, a, b, c, x( 7), S42, '432aff97'x) !  /* 50 */
          call round4(c, d, a, b, x(14), S43, 'ab9423a7'x) !  /* 51 */
          call round4(b, c, d, a, x( 5), S44, 'fc93a039'x) !  /* 52 */
          call round4(a, b, c, d, x(12), S41, '655b59c3'x) !  /* 53 */
          call round4(d, a, b, c, x( 3), S42, '8f0ccc92'x) !  /* 54 */
          call round4(c, d, a, b, x(10), S43, 'ffeff47d'x) !  /* 55 */
          call round4(b, c, d, a, x( 1), S44, '85845dd1'x) !  /* 56 */
          call round4(a, b, c, d, x( 8), S41, '6fa87e4f'x) !  /* 57 */
          call round4(d, a, b, c, x(15), S42, 'fe2ce6e0'x) !  /* 58 */
          call round4(c, d, a, b, x( 6), S43, 'a3014314'x) !  /* 59 */
          call round4(b, c, d, a, x(13), S44, '4e0811a1'x) !  /* 60 */
          call round4(a, b, c, d, x( 4), S41, 'f7537e82'x) !  /* 61 */
          call round4(d, a, b, c, x(11), S42, 'bd3af235'x) !  /* 62 */
          call round4(c, d, a, b, x( 2), S43, '2ad7d2bb'x) !  /* 63 */
          call round4(b, c, d, a, x( 9), S44, 'eb86d391'x) !  /* 64 */

        A=AA+A
        B=BB+B
        C=CC+C
        D=D+DD

c       if (i1.gt.ixx-3) write(6,'(i8,4z10)')k,a,b,c,d     
c       if (i1.eq.ixx) write(6,*)mess64

      enddo                     ! i1


c intermediate == return A B C D registers
        if (jtype.eq.0) then
           write(ans,81,iostat=ierr1)a,b,c,d,lenorig8b
           if (Ierr1.ne.0) ans='error_write_register'
           asrx_md5=ans
           return
        endif

c final, return md5 value in standard format           
       i4a=a
          write(ans(1:8),'(4(z2))')i1a
       i4a=b
          write(ans(9:16),'(4(z2))')i1a
       i4a=c
          write(ans(17:24),'(4(z2))')i1a
       i4a=d
          write(ans(25:32),'(4(z2))')i1a

c convert to lower case
       do il=1, 32
          icc=index('ABCDEF',ANS(IL:il))
          if (icc.gt.0) ans(il:il)=a1lc(icc)
       enddo
        
c       print *,' ans=',ans
c      write(6,'(4z10)')a,b,c,d     

      asrx_md5=ans(1:32)
      return
      end


C  /* round 1 to 4 functins */

        SUBROUTINE round1(a1,b1,c1,d1,kk,shift,sini)
        INTEGER A1,B1,C1,D1,Kk,SHIFT,SINI,T1,T2,f

        t1=a1+f(b1,c1,d1)+ kk + sini

        t2=ISHC(t1,shift)
        A1=T2+B1
        return 
        END


        SUBROUTINE round2(a1,b1,c1,d1,kk,shift,sini)
        INTEGER A1,B1,C1,D1,Kk,SHIFT,SINI,T1,T2,g

        t1=a1+G(b1,c1,d1)+ kk + sini
        t2=ISHC(t1,shift)
        A1=T2+B1
        return 
        END

        SUBROUTINE round3(a1,b1,c1,d1,kk,shift,sini)
        INTEGER A1,B1,C1,D1,Kk,SHIFT,SINI,T1,T2,h

        t1=a1+H(b1,c1,d1)+ kk + sini
        t2=ISHC(t1,shift)
        A1=T2+B1
        return 
        END


        SUBROUTINE round4(a1,b1,c1,d1,kk,shift,sini)
        INTEGER A1,B1,C1,D1,Kk,SHIFT,SINI,T1,T2,i

        t1=a1+I(b1,c1,d1)+ kk + sini
        t2=ISHC(t1,shift)
        A1=T2+B1
        return 
        END



c*********** Basic functions */
c* F(x, y, z) == (((x) & (y)) | ((~x) & (z))) */
        INTEGER FUNCTION f(X,Y,Z)
        INTEGER X,Y,Z,T1,NOTX,t2
        t1=Iand(x,y)
        notx=NOT(x)
        t2=Iand(notx,z)
        t2=Ior(t1,t2)
        f=t2
        RETURN
        END

c* G(x, y, z) == (((x) & (z)) | ((y) & (~z)))*/
        INTEGER FUNCTION G(X,Y,Z)
        INTEGER X,Y,Z,T1,NOTz,T2

        T1=Iand(x,z)
        notz=NOT(z)
        t2=Iand(y,notz)
        G=Ior(t1,t2)
        RETURN
        END

c* H(x, y, z) == ((x) ^ (y) ^ (z)) */
        INTEGER FUNCTION H(X,Y,Z)
        INTEGER X,Y,Z,T1

        t1=IEor(x,y)
        H=IEor(t1,z)
        RETURN
        END

c* I(x, y, z) == ((y) ^ ((x) | (~z))) */
        INTEGER FUNCTION I(X,Y,Z)
        INTEGER X,Y,Z,NOTz,T2

        notz=NOT(z)
        t2=Ior(x,notz)
        I=IEor(y,t2)
        RETURN
        END



c example of a rexx procedure that uses sequential md5 construction
c seq_md5_file:procedure 
c
c  parse arg afile              /* foo1 is the string to be md5'ized */
c
c  nbytes=stream(afile,'c','query size')
c  if nbytes='' | nbytes=0 then return ' '
c
c  foo=stream(afile,'c','open read')
c  if abbrev(translate(strip(foo)),'READY:')=0 then return ' '
c
c  gobble=64*500              /* 32k pieces -- any multiple of 64 is okay*/
c
c  if nbytes<= gobble then do   /* small string? do it all at once */
c      BOB=charin(afile,1,nbytes)
c      foo=stream(afile,'c','close')
c      md5=srx_md5(BOB)              
c      return md5
c  end                 /* else, do it in pieces */
c
c  p1=charin(afile,1,gobble)       /* get first piece */
c
c stuff=srx_md5(p1,0)            /* stuff contains A B C D components of md5 */
c if abbrev(stuff,'error_')=1 then do
c       say stuff
c       exit
c end 
c
c  iat=gobble+1  
c  iat2=iat+gobble-1   
c  do while iat2 <= nbytes        /* do  "intermediate" pieces */
c     p1=charin(AFILE,,gobble)
c     stuff=srx_md5(p1,0,stuff)        /* note recursive use of STUFF */
c     if abbrev(stuff,'error_')=1 then do
c         say stuff
c         exit
c    end 
c     iat=iat+gobble
c     iat2=iat+gobble-1   
c
c
c  end
c  p1=charin(AFILE,,1+NBYTES-IAT)
c   foo=stream(afile,'c','close')
c  md5=srx_md5(p1,1,stuff)      /* and compute md5 -- 1 signals "last piece" */
c
c  return md5
c
c
