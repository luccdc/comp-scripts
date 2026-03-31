# LUCCDC Competition Scripts
![](./bingus.png)

## Linux Perl Scripting
Absolute basics of Perl

### Variables
Variables in Perl are identifiers prefixed with a special symbol: `$` for scalar values, `@` for vector values, and `%` for hashes.
Scalars are simple: a number, a string, etc.

``` perl
my $a = 1;
my $b = "hello!";
my $c = qw{ abc }
```

Vectors are also simple: lists.

``` perl
my @a = (1, 2, 3);
my @b = ("Hello", "World");
my @c = qw{ goodbye world };

print $c[0];
```



Hashes are essentially keyed vectors.
``` perl
my %a = (
    a => 1,
    b => 2,
    c => 3,
);

print $a{a}
```
Why are we using `$a` when getting the value back out of the hash?
And the same for arrays: why `$c[0]` instead of `@c[0]`?
Well, it's because we're now looking for a scalar value: `a{a}` is going to be a scalar.


### References
You may also see hashes defined like this:
``` perl
my $a = {
    a => 1,
    b => 2,
    c => 3,
    d => 4,
};
print $a->{a}
```

The use of `{}` means "create an anonymous hash and return a reference."
So `$a` is actually a pointer to this hash, just like in C or C++.
We can then use the dereferencing operator `->` to get at the value stored in `$a`.

Vectors may be defined as follows:
``` perl
my $a = [1, 2, 3];
print join(", ", @{$a});
```
Just as `{}` creates an anonymous hash, `[]` creates an anonymous vector and returns a reference.

Note the use of `@{}` to dereference the array. 

`%{}` can be used on hashes, but it does not work intuitively the way `@{}` does.
Prefer using the dereferencing operator.

### Functions

Functions are created using `sub`, for 'subroutine'.
Name them with `snake_case`, using `imperativeverb_noun`.
``` perl
sub do_foo {

}
```

Every function receives a list of parameters, referred to with special variable `$_` (`@_` to access all of them as a list.).
The first line in your function should deconstruct this into the actual parameters you want.
``` perl
sub add_three_numbers {
    my ($a, $b, $c) = @_;
}
```



### Resources
- [Perl Best Practices](https://learning.oreilly.com/library/view/perl-best-practices/0596001738/)
- [Perl Secret Operators](https://metacpan.org/dist/perlsecret/view/lib/perlsecret.pod)
