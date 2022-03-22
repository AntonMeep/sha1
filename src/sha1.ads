with Ada.Streams; use Ada.Streams;

with SHA1_Generic;

package SHA1 is new SHA1_Generic
  (Element => Stream_Element, Index => Stream_Element_Offset,
   Element_Array => Stream_Element_Array);
