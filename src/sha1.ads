with Ada.Streams; use Ada.Streams;

with SHA1_Generic;

package SHA1 is new SHA1_Generic
  (Element       => Stream_Element, Index => Stream_Element_Offset,
   Element_Array => Stream_Element_Array) with
   Pure,
   Preelaborate;
--  @summary
--  Secure Hash Algorithm 1 in Ada, Ada.Streams interface
--
--  @description
--  This package contains an instantation of SHA1_Generic package with the
--  types from Ada.Streams package. This should be your default choice for
--  most applications, but you can always use the generic package in case your
--  program already defines own type representing a byte array.
--
--  See SHA1_Generic for more details
