//module for curve and e521 functionality
pub mod curve{
    pub mod e521;
}

// module for sha3 primitives
pub mod sha3{
    pub mod keccakf;
    pub mod sponge;
    pub mod aux_functions;
}

//module for model functions
pub mod model;

//module for gui-related functions
pub mod view{
    pub mod window;
}
