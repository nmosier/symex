#include "fpu.h"

namespace x86 {

const std::unordered_map<unsigned, std::pair<unsigned, unsigned>> FPUState::fp_ieee_bits = {
    {SINGLE_PREC_WIDTH, {8, 23 + 1}},
    {DOUBLE_PREC_WIDTH, {11, 52 + 1}},
    {EXTENDED_PREC_WIDTH, {15, 64 + 1}},
};

}
