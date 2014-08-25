/* 24 Oct 1999. Daniel Hellerstein, danielh@crosslink.net

 REXX_MD4: A "fully rexx" md4 digest procedure.

Usage:
   anmd4=REXX_MD4(a_string)
where 
  a_string is any string
  anmd4 will be the 32 character (hex character) MD4 digest.

Examples:

   a1=rexx_md4('abc')
   say " md4 of abc should be: a448017aaf21d8525fc10ae87aa6729d"
   say "  the value we got is:" a1


   a1=rexx_md4('ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789')
   say " md4 of ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789= "
   say "                           043f8582f241db351ce627e153e7f0e4 "
   say " the value we got is:" a1


Notes:

 *  As an "all REXX" procedure (no dll's), this uses REXX math.
    Thus -- it is NOT FAST.  For small strings it is
    toleable (0.10 seconds on a p166 for 50 character strings),
    but for larger strings (or files) it can take many seconds.

 *  For details on the MD4 digest, see the Internet RFC #1320
    (try http://theory.lcs.mit.edu/~rivest/rfc1321.txt7; or
    look for RFC1320 using your favorite search engine)
*/




/*  ------------------------------ */
/* this is an "all rexx" md4 procedure. It works, but it is slow */
rexx_md4:procedure             /* if called externally, remove the "procedure" */
parse arg stuff
numeric digits 11
lenstuff=length(stuff)

c0=d2c(0)
c1=d2c(128)
c1a=d2c(255)
c1111=c1a||c1a||c1a||c1a
slen=length(stuff)*8
slen512=slen//512

const1=c2d('5a827999'x)
const2=c2d('6ed9eba1'x)


/* pad message to multiple of 512 bits.  Last 2 words are 64 bit # bits in message*/
if slen512=448 then  addme=512
if slen512<448 then addme=448-slen512
if slen512>448 then addme=960-slen512
addwords=addme/8

apad=c1||copies(c0,addwords-1)

xlen=reverse(right(d2c(lenstuff*8),4,c0))||c0||c0||c0||c0  /* 2**32 max bytes in message */

/* NEWSTUFF is the message to be md4'ed */
newstuff=stuff||apad||xlen

/* starting values of registers */
 a ='67452301'x;
 b ='efcdab89'x;
 c ='98badcfe'x;
 d ='10325476'x;

lennews=length(newstuff)/4

/* loop through entire message */
do i1 = 0 to ((lennews/16)-1)
  i16=i1*64
  do j=1 to 16
     j4=((j-1)*4)+1
     jj=i16+j4
     m.j=reverse(substr(newstuff,jj,4))
  end /* do */

/* transform this block of 16 chars to 4 values. Save prior values first */
 aa=a;bb=b;cc=c;dd=d

/* do 3 rounds, 16 operations per round (rounds differ in bit'ing functions */
S11=3
S12=7 
S13=11
S14=19
  a=round1( a, b, c, d,   0 , S11); /* 1 */
  d=round1( d, a, b, c,   1 , S12); /* 2 */
  c=round1( c, d, a, b,   2 , S13); /* 3 */
  b=round1( b, c, d, a,   3 , S14); /* 4 */
  a=round1( a, b, c, d,   4 , S11); /* 5 */
  d=round1( d, a, b, c,   5 , S12); /* 6 */
  c=round1( c, d, a, b,   6 , S13); /* 7 */
  b=round1( b, c, d, a,   7 , S14); /* 8 */
  a=round1( a, b, c, d,   8 , S11); /* 9 */
  d=round1( d, a, b, c,   9 , S12); /* 10 */
  c=round1( c, d, a, b,  10 , S13); /* 11 */
  b=round1( b, c, d, a,  11 , S14); /* 12 */
  a=round1( a, b, c, d,  12 , S11); /* 13 */
  d=round1( d, a, b, c,  13 , S12); /* 14 */
  c=round1( c, d, a, b,  14 , S13); /* 15 */
  b=round1( b, c, d, a,  15 , S14); /* 16 */

  /* Round 2 */
S21=3
S22=5
S23=9 
S24=13
a= round2( a, b, c, d,   0 ,  S21 ); /* 17 */
d= round2( d, a, b, c,   4 ,  S22 ); /* 18 */
c=  round2( c, d, a, b,  8 , S23); /* 19 */
b=  round2( b, c, d, a,  12 , S24); /* 20 */
a=  round2( a, b, c, d,   1 , S21); /* 21 */
d=  round2( d, a, b, c,  5  , S22); /* 22 */
c=  round2( c, d, a, b,  9  , S23); /* 23 */
 b= round2( b, c, d, a,   13,  S24); /* 24 */
a= round2( a, b, c, d,   2 ,  S21); /* 25 */
d= round2( d, a, b, c,  6  ,  S22); /* 26 */
c=  round2( c, d, a, b,  10 , S23); /* 27 */
b=  round2( b, c, d, a,  14 , S24); /* 28 */
a=  round2( a, b, c, d,   3 , S21); /* 29 */
d=  round2( d, a, b, c,   7 , S22); /* 30 */
c=  round2( c, d, a, b,  11 , S23); /* 31 */
b= round2( b, c, d, a,  15 ,  S24) ; /* 32 */

  /* Round 3 */
S31= 3
S32= 9 
S33= 11
S34= 15
a= round3( a, b, c, d,   0 , S31) ; /* 33 */
d=  round3( d, a, b, c,   8 , S32); /* 34 */
c=  round3( c, d, a, b,  4  , S33); /* 35 */
b=  round3( b, c, d, a,  12 , S34); /* 36 */
a=  round3( a, b, c, d,   2 , S31); /* 37 */
d=  round3( d, a, b, c,  10 , S32); /* 38 */
c=  round3( c, d, a, b,   6 , S33); /* 39 */
b=  round3( b, c, d, a,  14 , S34); /* 40 */
a=  round3( a, b, c, d,  1  , S31); /* 41 */
d=  round3( d, a, b, c,   9 , S32); /* 42 */
c=  round3( c, d, a, b,   5 , S33); /* 43 */
b=  round3( b, c, d, a,  13 , S34); /* 44 */
a=  round3( a, b, c, d,   3 , S31); /* 45 */
d=  round3( d, a, b, c,  11 , S32); /* 46 */
c=  round3( c, d, a, b,   7 , S33); /* 47 */
b=  round3( b, c, d, a,  15 , S34); /* 48 */


a=m32add(aa,a) ; b=m32add(bb,b) ; c=m32add(cc,c) ; d=m32add(dd,d)

end

aa=c2x(reverse(a))||c2x(reverse(b))||c2x(reverse(C))||c2x(reverse(D))
return aa

/* round 1 to 3 functins */

round1:procedure expose m. c1111 c0 c1
parse arg a1,b1,c1,d1,kth,shift
kth=kth+1
t1=c2d(a1)+c2d(f(b1,c1,d1))+ c2d(m.kth) 
t1a=right(d2c(t1),4,c0)
t2=rotleft(t1a,shift)
return t2

round2:procedure expose m. c1111 c0 c1 const1
parse arg a1,b1,c1,d1,kth,shift
kth=kth+1
t1=c2d(a1)+c2d(g(b1,c1,d1))+ c2d(m.kth) + const1
t1a=right(d2c(t1),4,c0)
t2=rotleft(t1a,shift)
return t2

round3:procedure expose m. c1111 c0 c1 const2
parse arg a1,b1,c1,d1,kth,shift
kth=kth+1
t1=c2d(a1)+c2d(h(b1,c1,d1))+ c2d(m.kth) + const2 
t1a=right(d2c(t1),4,c0)
t2=rotleft(t1a,shift)
return t2

/* add to "char" numbers, modulo 2**32, return as char */
m32add:procedure expose c0 c1 c1111
parse arg v1,v2
t1=c2d(v1)+c2d(v2)
t2=d2c(t1)
t3=right(t2,4,c0)
return t3



/*********** Basic functions */
/* F(x, y, z) == (((x) & (y)) | ((~x) & (z))) */
f:procedure expose c0 c1 c1111 
parse arg x,y,z
t1=bitand(x,y)
notx=bitxor(x,c1111)
t2=bitand(notx,z)
return bitor(t1,t2)

/* G(x, y, z) == (((x) & (y)) | ((x) & (Z))|  ((y) & (z)) */
g:procedure expose c0 c1 c1111
parse arg x,y,z
t1=bitand(x,y)
t2=bitand(x,z)
t3=bitand(y,z)
t4=bitor(t1,t2)
return bitor(t4,t3)

/* H(x, y, z) == ((x) ^ (y) ^ (z)) */
h:procedure expose c0 c1 c1111
parse arg x,y,z
t1=bitxor(x,y)
return bitxor(t1,z)


/* bit rotate to the left by s positions */
rotleft:procedure 
parse arg achar,s
if s=0 then return achar

bits=x2b(c2x(achar))
lb=length(bits)
t1=left(bits,s)
t2=bits||t1
yib=right(t2,lb)
return x2c(b2x(yib))





