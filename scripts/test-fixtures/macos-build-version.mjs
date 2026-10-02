// Neutral, shortened `otool -l` shape; no private path or executable bytes.
export const VALID_MACOS_11_LOAD_COMMANDS = `Load command 0
      cmd LC_SEGMENT_64
  cmdsize 72
Load command 1
      cmd LC_BUILD_VERSION
  cmdsize 32
 platform 1
    minos 11.0
      sdk 26.5
   ntools 1
     tool 3
  version 1267.0
Load command 2
      cmd LC_LOAD_DYLINKER
  cmdsize 32
`;
