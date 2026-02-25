#pragma once

#include <ostream>

namespace Color {

    inline std::ostream& reset(std::ostream& os) { return os << "\033[0m"; }
    inline std::ostream& black(std::ostream& os) { return os << "\033[30m"; }
    inline std::ostream& red(std::ostream& os) { return os << "\033[31m"; }
    inline std::ostream& green(std::ostream& os) { return os << "\033[32m"; }
    inline std::ostream& yellow(std::ostream& os) { return os << "\033[33m"; }
    inline std::ostream& blue(std::ostream& os) { return os << "\033[34m"; }
    inline std::ostream& magenta(std::ostream& os) { return os << "\033[35m"; }
    inline std::ostream& cyan(std::ostream& os) { return os << "\033[36m"; }
    inline std::ostream& white(std::ostream& os) { return os << "\033[37m"; }

    inline std::ostream& bright_black(std::ostream& os) { return os << "\033[90m"; }
    inline std::ostream& bright_red(std::ostream& os) { return os << "\033[91m"; }
    inline std::ostream& bright_green(std::ostream& os) { return os << "\033[92m"; }
    inline std::ostream& bright_yellow(std::ostream& os) { return os << "\033[93m"; }
    inline std::ostream& bright_blue(std::ostream& os) { return os << "\033[94m"; }
    inline std::ostream& bright_magenta(std::ostream& os) { return os << "\033[95m"; }
    inline std::ostream& bright_cyan(std::ostream& os) { return os << "\033[96m"; }
    inline std::ostream& bright_white(std::ostream& os) { return os << "\033[97m"; }

    inline std::ostream& bg_black(std::ostream& os) { return os << "\033[40m"; }
    inline std::ostream& bg_red(std::ostream& os) { return os << "\033[41m"; }
    inline std::ostream& bg_green(std::ostream& os) { return os << "\033[42m"; }
    inline std::ostream& bg_yellow(std::ostream& os) { return os << "\033[43m"; }
    inline std::ostream& bg_blue(std::ostream& os) { return os << "\033[44m"; }
    inline std::ostream& bg_magenta(std::ostream& os) { return os << "\033[45m"; }
    inline std::ostream& bg_cyan(std::ostream& os) { return os << "\033[46m"; }
    inline std::ostream& bg_white(std::ostream& os) { return os << "\033[47m"; }

    inline std::ostream& bold(std::ostream& os) { return os << "\033[1m"; }
    inline std::ostream& dim(std::ostream& os) { return os << "\033[2m"; }
    inline std::ostream& italic(std::ostream& os) { return os << "\033[3m"; }
    inline std::ostream& underline(std::ostream& os) { return os << "\033[4m"; }

} // namespace Color

/*
 * VERWENDUNG:
 *
 *   std::cout << Color::yellow << "Mutated: " << Color::reset << buffer << "\n";
 *   std::cout << Color::bold << Color::red << "Fehler!" << Color::reset << "\n";
 */