# Rust Implementation of SHA256

This is based off my [original implementation in CWEB](https://github.com/bcr/sha256).

## Usage

```rust
let mut sha256 = Sha256::new();
sha256.update("abc".as_bytes());
let actual = sha256.do_final();
```

* Use `Sha256::new` to make a new instance
* Call `update` or `update_other` as many times as you want
* Call `do_final` and get your `[u8; 32]` with the completed digest
* Look at the unit tests
* Look at `main.rs`

## TIL Know When to Break The Rules

### Integer Wrapping

The first major issue I ran into was the modulo math required. In C, you can
party hard and overflow a 32 bit integer and it happily lets you do it. Rust
gets all humpty and tries to protect you. So I learned about the use of
`Wrapping` to get around this, which coincidentally has this in
[the documentation](https://doc.rust-lang.org/stable/std/num/struct.Wrapping.html):

```...some code explicitly expects and relies upon modular arithmetic (e.g., hashing).```

Yes it does. I believe I am the target audience for this functionality and I
feel no shame in using it.

### Rust Style Conventions

When implementing something from a specification, I think it's important to
keep the fidelity of the specification whenever possible. In the case of
SHA256, there are various variable names and function names that are
specified. For instance, here is an underlying function, $\Sigma_0$, and my
Rust implementation:

$$\Sigma_0^{\{256\}}(x) = (x \ggg 2) \oplus (x \ggg 13) \oplus (x \ggg 22)$$

```rust
fn Sigma0(x: Wrapping<u32>) -> Wrapping<u32> {
    Wrapping(rotr(x.0, 2) ^ rotr(x.0, 13) ^ rotr(x.0, 22))
}
```

And there is also a $\Sigma_1$ function:

$$\Sigma_1^{\{256\}}(x) = (x \ggg 6) \oplus (x \ggg 11) \oplus (x \ggg 25)$$

```rust
fn Sigma1(x: Wrapping<u32>) -> Wrapping<u32> {
    Wrapping(rotr(x.0, 6) ^ rotr(x.0, 11) ^ rotr(x.0, 25))
}
```

Note that these function names do not follow the snake_case convention.

```
warning: function `Sigma0` should have a snake case name
warning: function `Sigma1` should have a snake case name
```

I could have been even meaner and done this:

```rust
fn Σ0(x: Wrapping<u32>) -> Wrapping<u32> {
    Wrapping(rotr(x.0, 2) ^ rotr(x.0, 13) ^ rotr(x.0, 22))
}
```

And I'm not sure I won't... Where does my fear of UTF-8 end and my need for
specification fidelity begin...

The adherence to the Rust naming convention is secondary to the intent from the
specification. One obvious argument is maintinability -- providing an
unsurprising environment that someone else can maintain. However, anyone who
would ever need to repair the implementation would be doing so by repairing an
inconsistency between the implementation and the specification, and all of the
Rust formatting conventions in the world aren't going to help you understand the
algorithm. So I would rather be unsurprising to the domain expert rather than
unsurprising to an uninitiated Rust developer.

## TIL About Iterators

So I got tripped up by iterators. I have the following:

```rust
pub fn update<'a, T>(&mut self, data: T)
where
    T: IntoIterator<Item = &'a u8>,
{
    self.update_other(data.into_iter().map(|x| *x));
}

pub fn update_other<T>(&mut self, data: T)
where
    T: IntoIterator<Item = u8>,
{
    for this_byte in data {
        // ... blah blah blah do something with this_byte: u8
    }
}
```

This is because I have two ways I use it:

```rust
sha256.update("abc".as_bytes());
```

```rust
sha256.update_other((0..1_000_000).map(|_| b'a'));
sha256.update_other(io::stdin().bytes().map(|x| x.unwrap()));
```

The `stdin` case is particularly hilarious because every byte is a `Result`
with a potential I/O error. You shall panic and like it. Just give me my `u8`.

There is more learning to do here. I am not one with the ownership.
