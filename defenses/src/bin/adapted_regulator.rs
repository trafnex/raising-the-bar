// Adapted RegulaTor -- an approximation of the RegulaTor defense, modified for
// video traffic.
// Code from the paper: David Hasselquist, Ethan Witwer, August Carlson, Niklas
// Johansson, and Niklas Carlsson. "Raising the Bar: Improved Fingerprinting
// Attacks and Defenses for Video Streaming Traffic". Proceedings on Privacy
// Enhancing Technologies (PoPETs), volume 4, 2024.
// If you use this code in your work, please include a reference to the paper
// and the RegulaTor/Maybenot papers, which the code is based on (more details
// in README.md).

use std::env;
use std::f64::INFINITY;
use std::collections::HashMap;

use maybenot::{
constants::STATEEND,
machine::Machine,
event::Event,
state::State,
dist::{Dist, DistType}
};


// Relay machine states
const BLOCK_STATE_INDEX: usize = 1;
const FIRST_SEND_STATE_INDEX: usize = 2;

// Shared constants
const PACKET_SIZE: f64 = 1500.0;


fn main() {
    let args: Vec<String> = env::args().collect();
    assert!(args.len() == 5, "Usage: {} <initial rate> <decay rate> <upload ratio> <packets per state>", &args[0]);
    
    let initial_rate:      f64 = args[1].parse().expect("Invalid initial rate");      // RegulaTor param = R, initial surge rate (packets / sec)
    let decay_rate:        f64 = args[2].parse().expect("Invalid decay rate");        // RegulaTor param = D, decay rate
    let upload_ratio:      f64 = args[3].parse().expect("Invalid upload ratio");      // RegulaTor param = U, upload ratio
    let packets_per_state: f64 = args[4].parse().expect("Invalid packets per state"); // number of packets per state (approximation granularity)
    
    let relay_machine = generate_relay_machine(packets_per_state, initial_rate, decay_rate);
    println!("Relay machine: {} ({})\n", relay_machine, relay_machine.len());

    let client_machine = generate_client_machine(upload_ratio);
    println!("Client machine: {} ({})\n", client_machine, client_machine.len());
}


// Generate an Adapted RegulaTor client-side machine.
fn generate_client_machine(upload_ratio: f64) -> String {
    // Set up state vector
    let num_states = (upload_ratio as usize) + 1;
    let prob_last_trans = 1.0 - upload_ratio.fract();
    
    let mut states: Vec<State> = Vec::with_capacity(num_states);
    
    // COUNTER states
    for i in 1..num_states {
        let mut prob_trans = 1.0;
        if i == num_states - 1 {
            prob_trans = prob_last_trans;
        }
        
        states.push(generate_client_count_state(i - 1, i, num_states, prob_trans));
    }
    
    // SEND state
    states.push(generate_client_send_state(num_states));
    
    // Machine
    let machine = Machine {
        allowed_padding_bytes: 0,
        max_padding_frac: 0.0,
        allowed_blocked_microsec: 0,
        max_blocking_frac: 0.0,
        states: states,
        include_small_packets: false,
    };
    
    return machine.serialize();
}


// Generate the SEND state for a client-side machine.
fn generate_client_send_state(num_states: usize) -> State {
    // PaddingSent --> COUNT_0 (100%)
    let mut padding_sent: HashMap<usize, f64> = HashMap::new();
    padding_sent.insert(0, 1.0);
    
    // Transitions
    let mut transitions: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    transitions.insert(Event::PaddingSent, padding_sent);
    
    // SEND state
    let mut state = State::new(transitions, num_states);
    state.bypass = true;
    state.replace = true;
    
    state.timeout = Dist {
        dist: DistType::Uniform,
        param1: 0.0,
        param2: 0.0,
        start: 0.0,
        max: 0.0,
    };
    
    state.action = Dist {
        dist: DistType::Uniform,
        param1: PACKET_SIZE,
        param2: PACKET_SIZE,
        start: 0.0,
        max: 0.0,
    };
    
    return state;
}


// Generate a COUNT state for a client-side machine.
fn generate_client_count_state(curr_index: usize, next_index: usize, num_states: usize, prob_trans: f64) -> State {
    // PaddingRecv --> COUNT_[i+1] (prob_trans)
    let mut padding_recv: HashMap<usize, f64> = HashMap::new();
    padding_recv.insert(next_index, prob_trans);
    if prob_trans < 1.0 {
        padding_recv.insert(curr_index, 1.0 - prob_trans);
    }
    
    // NonPaddingRecv --> COUNT_[i+1] (prob_trans)
    let mut nonpadding_recv: HashMap<usize, f64> = HashMap::new();
    nonpadding_recv.insert(next_index, prob_trans);
    if prob_trans < 1.0 {
        nonpadding_recv.insert(curr_index, 1.0 - prob_trans);
    }
    
    // LimitReached --> COUNT_[i+1] (100%)
    let mut limit_reached: HashMap<usize, f64> = HashMap::new();
    limit_reached.insert(next_index, 1.0);
    
    // Transitions
    let mut transitions: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    transitions.insert(Event::PaddingRecv, padding_recv);
    transitions.insert(Event::NonPaddingRecv, nonpadding_recv);
    if prob_trans < 1.0 {
        transitions.insert(Event::LimitReached, limit_reached);
    }
    
    // COUNT_i state
    let mut state = State::new(transitions, num_states);
    state.action_is_block = true;
    state.bypass = true;
    state.replace = true;
    
    state.timeout = Dist {
        dist: DistType::Uniform,
        param1: 0.0,
        param2: 0.0,
        start: 0.0,
        max: 0.0,
    };
    
    state.action = Dist {
        dist: DistType::Uniform,
        param1: INFINITY,
        param2: INFINITY,
        start: 0.0,
        max: 0.0,
    };
    
    state.limit = Dist {
        dist: DistType::Uniform,
        param1: 2.0,
        param2: 2.0,
        start: 0.0,
        max: 0.0,
    };
    
    return state;
}


// Generate an Adapted RegulaTor relay-side machine.
fn generate_relay_machine(packets_per_state: f64, initial_rate: f64, decay: f64) -> String {
    let mut t1 = 0.0;
    let mut keep_going = true;
    let mut num_send_states = 0;
    
    // Calculate number of send states
    while keep_going {
        let width = calc_interval_width(t1, packets_per_state, initial_rate, decay);
        let middle = t1 + (width / 2.0);
        let t2 = t1 + width;
        
        if width == INFINITY || calculate_rate(middle, initial_rate, decay) < 1.0 {
            keep_going = false;
        }
        
        t1 = t2;
        num_send_states += 1;
    }
    
    // Set up state vector
    let num_states = num_send_states + 2;
    let mut states: Vec<State> = Vec::with_capacity(num_states);
    
    // START and BLOCK states
    states.push(generate_relay_start_state(num_states));
    states.push(generate_relay_block_state(num_states));
    
    // SEND states
    t1 = 0.0;
    
    for i in 0..num_send_states {
        let width = calc_interval_width(t1, packets_per_state, initial_rate, decay);
        let middle = t1 + (width / 2.0);
        let t2 = t1 + width;
        
        let mut rate = calculate_rate(middle, initial_rate, decay);
        let mut next_idx = i + FIRST_SEND_STATE_INDEX + 1;
        let curr_idx = i + FIRST_SEND_STATE_INDEX;
        
        if width == INFINITY || rate < 1.0 {
            rate = 1.0;
            next_idx = STATEEND;
        }
        
        states.push(generate_relay_send_state(curr_idx, next_idx, num_states, packets_per_state, 1000000.0 / rate, rate));
        
        t1 = t2;
    }
    
    // Machine
    let machine = Machine {
        allowed_padding_bytes: 0,
        max_padding_frac: 0.0,
        allowed_blocked_microsec: 0,
        max_blocking_frac: 0.0,
        states: states,
        include_small_packets: false,
    };
    
    return machine.serialize();
}


// Generate a SEND state for a relay-side machine.
fn generate_relay_send_state(curr_index: usize, next_index: usize, num_states: usize, padding_count: f64, timeout: f64, rate: f64) -> State {
    // PaddingSent --> SEND_i (100%)
    let mut padding_sent: HashMap<usize, f64> = HashMap::new();
    padding_sent.insert(curr_index, 1.0);
    
    // LimitReached --> SEND_[i+1] or loop around (100%)
    let mut limit_reached: HashMap<usize, f64> = HashMap::new();
    limit_reached.insert(next_index, 1.0);
    
    // NonPaddingSent --> SEND_0 (100%) if rate < 200.0
    let mut nonpadding_sent: HashMap<usize, f64> = HashMap::new();
    nonpadding_sent.insert(FIRST_SEND_STATE_INDEX, 1.0);

    // Transitions
    let mut transitions: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    transitions.insert(Event::PaddingSent, padding_sent);
    transitions.insert(Event::LimitReached, limit_reached);
    if rate < 200.0 {
        transitions.insert(Event::NonPaddingSent, nonpadding_sent);
    }
    
    // SEND_i state
    let mut state = State::new(transitions, num_states);
    state.bypass = true;
    state.replace = true;
    
    state.timeout = Dist {
        dist: DistType::Uniform,
        param1: timeout,
        param2: timeout,
        start: 0.0,
        max: 0.0,
    };
    
    state.action = Dist {
        dist: DistType::Uniform,
        param1: PACKET_SIZE,
        param2: PACKET_SIZE,
        start: 0.0,
        max: 0.0,
    };
    
    state.limit = Dist {
        dist: DistType::Uniform,
        param1: padding_count,
        param2: padding_count,
        start: 0.0,
        max: 0.0,
    };
    
    return state;
}


// Generate the BLOCK state for a relay-side machine.
fn generate_relay_block_state(num_states: usize) -> State {
    // BlockingBegin --> SEND_0 (100%)
    let mut blocking_begin: HashMap<usize, f64> = HashMap::new();
    blocking_begin.insert(FIRST_SEND_STATE_INDEX, 1.0);
    
    // Transitions
    let mut transitions: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    transitions.insert(Event::BlockingBegin, blocking_begin);
    
    // BLOCK state
    let mut state = State::new(transitions, num_states);
    state.action_is_block = true;
    state.bypass = true;
    state.replace = true;
    
    state.timeout = Dist {
        dist: DistType::Uniform,
        param1: 0.0,
        param2: 0.0,
        start: 0.0,
        max: 0.0,
    };
    
    state.action = Dist {
        dist: DistType::Uniform,
        param1: INFINITY,
        param2: INFINITY,
        start: 0.0,
        max: 0.0,
    };
    
    return state;
}


// Generate the START state for a relay-side machine.
fn generate_relay_start_state(num_states: usize) -> State {
    // NonPaddingSent --> BLOCK (100%)
    let mut nonpadding_sent: HashMap<usize, f64> = HashMap::new();
    nonpadding_sent.insert(BLOCK_STATE_INDEX, 1.0);
    
    // Transitions
    let mut transitions: HashMap<Event, HashMap<usize, f64>> = HashMap::new();
    transitions.insert(Event::NonPaddingSent, nonpadding_sent);
    
    return State::new(transitions, num_states);
}


// Find the width of an interval of the function RD^t, from a, with the specified packet count.
fn calc_interval_width(a: f64, count: f64, rate: f64, decay: f64) -> f64 {
    let mut mid = a;
    let mut step: f64 = 0.5;
    let mut decreasing = false;
    
    let mut curr_count = 0.0;
    let mut curr_diff = count - curr_count;
    
    while curr_diff.abs() > 0.00001 {
        if curr_diff < 0.0 {
            mid -= step;
            decreasing = true;
        } else {
            mid += step;
        }
        
        if decreasing {
            step /= 2.0;
        } else {
            step *= 2.0;
        }
        
        curr_count = calculate_rate(mid, rate, decay) * (mid - a) * 2.0;
        curr_diff = count - curr_count;
    }
    
    return (mid - a) * 2.0;
}


// RD^t
fn calculate_rate(t: f64, initial_rate: f64, decay: f64) -> f64 {
    return initial_rate * decay.powf(t);
}
