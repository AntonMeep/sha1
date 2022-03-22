with Ada.Streams; use Ada.Streams;
with Interfaces;

package SHA1 with
   Pure,
   Preelaborate
is
   Digest_Length : constant Stream_Element_Offset := 20;
   Block_Length  : constant Stream_Element_Offset := 64;

   subtype Digest is Stream_Element_Array (0 .. Digest_Length - 1);

   type Context is private;

   function Initialize return Context;
   procedure Initialize (Ctx : out Context);

   procedure Update (Ctx : in out Context; Input : String);
   procedure Update (Ctx : in out Context; Input : Stream_Element_Array);

   function Finalize (Ctx : in out Context) return Digest;
   procedure Finalize (Ctx : in out Context; Output : out Digest);

   function Hash (Input : String) return Digest;
   function Hash (Input : Stream_Element_Array) return Digest;
private
   use Interfaces;

   subtype Block is Stream_Element_Array (0 .. Block_Length - 1);

   type State_Array is array (Natural range 0 .. 4) of Unsigned_32;

   type Context is record
      State : State_Array :=
        (16#6745_2301#, 16#EFCD_AB89#, 16#98BA_DCFE#, 16#1032_5476#,
         16#C3D2_E1F0#);

      Count        : Stream_Element_Offset := 0;
      Buffer       : Block;
      Buffer_Index : Stream_Element_Offset := 0;
   end record;

   procedure Transform (State : in out State_Array; Buffer : Block);
   function Ch (X, Y, Z : Unsigned_32) return Unsigned_32;
   function Parity (X, Y, Z : Unsigned_32) return Unsigned_32;
   function Maj (X, Y, Z : Unsigned_32) return Unsigned_32;
end SHA1;
