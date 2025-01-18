---
title: Encrypted Operations - InCTF Internationals 2021
date:  2021-08-20 12:30:06
author: Vishvesh
author_url: https://twitter.com/The_Str1d3r
mathjax: true
categories:
  - Crypto
tags:
  - InCTFi
---

**tl;dr**

+  Multiplying the middle element of 3x3 matrix with 9 gets thesum of all elements.
+  Adding the least element of 5x4 matrix with the larget and multiplying this result by 10 gets the sum of all elements.
+  multiplying any row with 2000 and subtrating that number by 2 will get you the sum.
+  Remaing two rows can be filled with the result of subtracting 9 from each digit of a corresponding row . 

<!--more-->

**Challenge Points**: 823
**Challenge Author**: [stryd3r](https://twitter.com/The_Str1d3r)


## Challenge Description

lets see how good you are at performing blind operations.

## Overview

We are provided with 2 files in c++. 
1. `level.cpp` has two functions `level1()` and `level2()`

2. `utils.cpp` This contains some standard utility functions for parsing converting and encryption and decryption  methods for FHE.

From the challenge description given in `level.cpp` and briefly going through both the levels we can assume that we need to work on encrypted data throughout performing certain set of operations on it such that the decrypted value will pass some checks.

Lets analyse both the level functions one by one....

<br/>

## The Approach

### 1. Analysing **level1()**

#### a) Level 1 - Part 1

Looking at this function we see in the begining a $20×20$ square matrix is being generated
```cpp=
    int SIZE = 20;
    int val = Genrand(1,500,0);
   
    std::vector<std::vector<int> > m(SIZE, std::vector<int>(SIZE));
    std::vector<std::vector<int> > v(169, std::vector<int>(9));
    std::vector<int> mat;

    for(int x = 0; x < SIZE; x++){ 
        for(int y = 0; y < SIZE; y++){
            m[x][y] = ++val;
        }
    }
```

We can see that a number is chosen randomly between $1$ and $500$ and that consequently is incremented by one resulting in $400$ consecuitve values with the random number being the initial state. All these $400$ values make up the $20×20$ matrix.


Moving on we see a bunch of for loops and allthough it might seem a bit complicated, simply executing this on any matrix and comparing the output with the original matrix values will tell us this is basically a collection of submatrices of the form $3×3$ that can be generated from the original matrix.
```cpp=
    int d = m.size();
    int r = 3;
    int c = 3;

    for (int i = 0; i < d-r+1; i++) {   
        for (int j = 0; j < d-c+1; j++) {
            for (int p = 0; p < r; p++) {
                for (int q = 0; q < c; q++) {
                    mat.push_back(m[i+p][j+q]);
                }
            }
        }
    }
```
Now we come to the first challenge. Looking at the below code snippet...
```cpp=
    idx = Genrand(0,v.size()-1,0);
    std::vector<int64_t> temp2(begin(v[idx]), end(v[idx]));
    msgvector = temp2;    
    
    FheEncrypt(msgvector);
```
here the plaintext vector which is encrypted by FHE is a $3×3$ sub matrix which is randomly chosen from the above list of submatrices. 
We can look at the check in the if condition ----->

```cpp=
  if (p[0] == sum)
    std::cout<<"Seems like you got a hang of this!!\nCongrats on completing the first level.\nGo get the flag!";
  else
    exit(0);
```

So we somehow need to make the first element of the plaintext vector p contain the sum of all elements in the randomly chosen $3×3$ sub matrix.

The server lets us pass a long int vector which we can create. we see the following operations are possible:
- Adiition (**+**)
- Multiplication (**\***)
- Vector Shift ( samt [*int*] -> shift amount ) 
    - left shift (**<**)
    - right shift (**>**)

So here the trick is to basically multiply the middle number of the $3\times3$ sub matrix with 9 and then do left shift 4 times to bring that number in 0th index of the vector!

The following set of input when sent to the corresponding prompts in the server will clear the first check in level 1:
- **{0,0,0,0,9,0,0,0,0}** &nbsp;&nbsp;&nbsp; *any vector with middle element with 9*
- **\***
- **1**
- **y** 
- **{0}** &nbsp;&nbsp;&nbsp;*any vector*
- **<**
- **4**
- **n**

Now onto the second part of level 2. 

#### b) Level 1 - Part 2

If you look at the code you will notice it is litrally a copy paste of the 
part 1 code. only difference is in the initial value assigned to matrix variables.
```cpp=
 DIFFERENCE:

  > part 1
    r = 3;
    c = 3;
    
  > part 2
    r = 5;
    c = 4;
```
So here the sub matrices generated are of dimension $5×4$ instead of $3×3$ as in part 1.
sum of such a matrix can be calculated by $(first element + last element)\times10$

we need at least one element either first or last to do this below we recover the first element: 

But there is one difference this time. a function which calculates a determinant is called twice and the resultant value is multiplied with the first element of $5\times4$ matrix, $num$
```cpp=
calc_determinant(a, 2 * x) - calc_determinant(a, x);
gen_hint(a, x);
cout << "This might make it easier: " << res * num << "\n\n";
```
A  gen_hint() function is called with the variables used in the determinant and we are allowed to perforem some operations on these variables.

if we take $g(x)$ as the function which calculates the determinant ($a$ is a constant) then $g(x) = a(a+x)^{2}$ (reducing eqn in `calc_determinant()`)

so $g(2x) - g(x) = a(a+2x)^{2} - a(a+x)$
which gives $ax(2a+3x)$

in `gen_hint()` we see $hint*ax$ so we need hint to be $(2a+3x)$ 
we give the following inputs:
- **{2 3}**
- **\***
- **1** 
- **n**
and for choice we give '**+**'
 
 now we have $hint = ax(2a+3x)$
 and we have $ax(2a+3x)*num$ ( $num$ being first element of $5\times4$ matrix)
 now dividing above two numbers we can obtain $num$
Again we need the 1st element of plaintext vector to be the sum of the sub matrix elements.

The following set of inputs will clear the part 2 check
- **{0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,`num`}** &nbsp;&nbsp;&nbsp; *any vector with last element `var1`*
- **+**
- **1** 
- **y**
- **{0}** &nbsp;&nbsp;&nbsp; *any vector*
- **<**
- **19**
- **y**
- **{10}**
- **\***
- **1** 
- **n**

### 2. Analysing **level2()**

Here we see a $5×5$ square matrix is generated initially assigned with random 1 digit values. Also the matrix index is always referenced through a randomly shuffled array containg the index values. But while assigning we notice for certain index value of the rows the whole row initialsed with $0's$
>Also note on line 3 below that matrix row indices are stored in an array which is then shuffled.
```cpp=
    std::vector<std::vector<int64_t> > m1(MAT_SIZE, std::vector<int64_t>(MAT_SIZE));

    std::vector<int> row = {0,1,2,3,4};

    std::random_device rd;
    std::mt19937 g(rd());
 
    std::shuffle(row.begin(), row.end(), g);
 
    std::cout <<"\n\n--------LEVEL2---------\n\n";

    for(int x = 0; x < MAT_SIZE; x++){ 
       for(int y = 0; y < MAT_SIZE; y++){
            if((x==row[0])||(x==row[1]))
                m1[x][y] = 0;
            else 
                m1[x][y] = Genrand(LOW,HIGH,0);
        }
    }
```

Right after generation a row of the matrix is encrypted and we are again provided with the three usual prompts.
Since we have not yet come across any check lets continue going through the code till we do.

Continuing through the code we come across two encryptions and both are encrypting an unknown (but distinct) row of the matrix and the reulting plaintext which is decrypted after the operations are performed on it is then added to the matrix rather a row is modified so that the new values of the row are the values of the plaintext vector. And the rows being modified are the ones which were earlier assigned with 0's.

After modifying the matrix we see that the matrix row's are basically being converted from 5 independent vectors to 5 numbers consisting of 5 digits
so from ecah row we are parsing a 5 digit number and consequently we can see that all these numbers are added and their sum is stored.
```cpp=
    for (int i = 0; i < 5; i++)
        if(i == row[1])
            numVec.push_back(VecToNum(p1));
        else if(i == row[0])
            numVec.push_back(VecToNum(p2));
        else
            numVec.push_back(VecToNum(m1[i]));

    long int sum = accumulate(numVec.begin(), numVec.end(), 0);
```

Now we come to the final check -------->
 ```cpp=
                                 Final Check
   if(sum==userInp){
        std::cout<<"\n\nYou have mastered encrypted operatoins!!\n";
        std::cout<<"Here's the flag: inctf{l0g1c_4nd_m4th_1s_4ll_1t_t00k!!}\n";     
    }
    else{
        std::cout<<"That was close, great going, But no flag for you!!\n\n";
        exit(0);
    }
```
Bringing all this together we finally get a idea of what is happening....


A $5×5$ square matrix is generated with 2 rows intialized with null values.
we are given an encrypted row to perform operations on and the resulting plaintext is stored in `userinp`.

Next 2 rows are encrypted and the resulting plaintext is assigned to each of the 2 rows that were initialised with $0's$ in the begining.
And then all 5 rows are converted to corrsponding 5 digit numbers and their sum is taken this sum is checked with the initial `userinp`. A sucessfull check yeilds the flag. 


So the first encrypted operations part, we are basically predicting what the sum will be.
And in the second part where the two rows are modifed we are basically setting those rows such that the sum will is forced to be what we predicted earlier.

+ So to get a correct predictoin of the sum we just need two add the digit 2 at the beginng of the 5 digit number in question and subtract 2 from the last digit*

+ Now to set the values of the row vectors such that the resulting two rows and the rest of the 3 rows add up to our predicted values we need to subtract each digit of the row or inthis case each element of the two rows with 9.*

+ since its a $5x5$ grid and we have generated two rows subtracting the other two rows with so when you add 4 out of these 5, 5 digit numbers we basicalli and up with $99999 + 99999$ ( since each of the two rows add up to $9$) and now we are left with the 5th row. Now if we add 2 to the sum of the 4 rows ie $99999 + 1 + 99999 + 1$ we get $200000$ and add this to the 5th number and subtract two and we get the final sum off all 5 numbers and this is exactly what we are doing in the prediction step.

+ we can also multiply the two rows with -1 and that will cancel out the result, the above method is without having any negetive digits in the vectors 

#### Final set of inputs..

The following set of input when sent to the corresponding prompts in the server will clear the check in level 2:

- ##### *1st set of inputs*
    
    - **{0}** &nbsp;&nbsp;&nbsp; *any vector will suffice*
    - **>**
    - **1**
    - **y** 
    - **{2}** 
    - **+**
    - **1**
    - **y** 
    - **{0,0,0,0,0,-2}**
    - **+**
    - **1** 
    - **n**
    
- ##### *2nd set of inputs*

    - **{-9,-9,-9,-9,-9}** 
    - **+**
    - **1** 
    - **y**
    - **{-1,-1,-1,-1,-1}**
    - **\***
    - **1**
    - **n**

- ##### *3rd set of inputs*

    - **{-9,-9,-9,-9,-9}** 
    - **+**
    - **0** 
    - **y**
    - **{-1,-1,-1,-1,-1}**
    - **\***
    - **1**
    - **n**


<br/>

## Conclusion

***WITH THAT U HAVE PASSED ALL THREE CHECKS!!!!!!***

You can find the full exploit [here](https://gist.github.com/Vishvesh-rao/138489667dc8f79ae8aa7bef8b7e5ebf).

flag: ```inctfi{m4st3r_0f_Encrypt3d_0p3r4t1on5_B3c0m3_u_H4v3!!}```