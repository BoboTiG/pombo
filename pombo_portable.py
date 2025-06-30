#!/usr/bin/env python3
# coding: utf-8
"""
Pombo
Theft-recovery tracking open-source software
https://github.com/BoboTiG/pombo
http://sebsauvage.net/pombo

This program is distributed under the OSI-certified zlib/libpnglicense .
http://www.opensource.org/licenses/zlib-license.php

This software is provided 'as-is', without any express or implied warranty.
In no event will the authors be held liable for any damages arising from
the use of this software.

Permission is granted to anyone to use this software for any purpose,
including commercial applications, and to alter it and redistribute it freely,
subject to the following restrictions:

    1. The origin of this software must not be misrepresented; you must not
       claim that you wrote the original software. If you use this software
       in a product, an acknowledgment in the product documentation would be
       appreciated but is not required.

    2. Altered source versions must be plainly marked as such, and must not
       be misrepresented as being the original software.

    3. This notice may not be removed or altered from any source distribution.
"""

from pombo import *


class PomboPortable(Pombo):
    """ Pombo Portable core. """

    conf = "pombo.conf" if WINDOWS else "pombo.conf"
    ip_file = "pombo" if WINDOWS else "pombo"
    log_file = "pombo.log" if WINDOWS else "pombo.log"


def main_portable(args):
    # type: (List[str]) -> int
    """ Usage example. """

    ret = 0

    try:
        if args and args[0] != "check":
            parser = PomboArg()
            ret = parser.parse(args[0])
        else:
            pombo = PomboPortable(testing="check" in args)
            pombo.work()
    except KeyboardInterrupt:
        printerr("*** STOPPING operations ***")
        ret = 1
    except Exception as ex:
        printerr(str(ex))
        raise

    return ret


if __name__ == "__main__":
    # pylint: disable=no-value-for-parameter
    sys.exit(main_portable(sys.argv[1:]))
