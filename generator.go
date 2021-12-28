package main

import (
	"fmt"
	"math/rand"
)

func DisplayPrime(num uint64, prime []bool) (p uint64) {
	for i := num; i >= 3; i-- {
		if prime[i] == false {
			p = i
			fmt.Printf("prime number: %d\n", p)
			return p
		}
	}
	return 0
}

func Sieve(num uint64) uint64 {
	prime := make([]bool, num+1)

	for i := uint64(0); i < num+1; i++ {
		prime[i] = false
	}

	for i := uint64(2); i*i <= num; i++ {
		if prime[i] == false {
			for j := i * 2; j <= num; j += i {
				prime[j] = true // cross
			}
		}

	}
	return DisplayPrime(num, prime)
}

func MEPower(x int, e int, m int) int {
	var res = 1

	for e > 0 {
		if (e % 2) == 1 {
			res = (res * x) % m
			e--
		} else {
			x = (x * x) % m
			e = e / 2
		}
	}

	return res
}

func FermatIsPrime(n uint64, k int) bool {
	if n%2 == 0 && n != 2 {
		return false
	}

	if n <= 3 {
		return true
	}

	for k > 0 {
		a := rand.Intn(int(n)-1) + 2
		if MEPower(a, int(n)-1, int(n)) != 1 {
			return false
		}
		k--
	}

	return true
}
