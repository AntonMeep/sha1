with Interfaces;

generic
   type Element is mod <>;
   type Index is range <>;
   type Element_Array is array (Index range <>) of Element;
package SHA1_Generic with
   Pure,
   Preelaborate
is
   Digest_Length : constant Index := 20;
   Block_Length  : constant Index := 64;

   subtype Digest is Element_Array (0 .. Digest_Length - 1);

   type Context is private;

   function Initialize return Context;
   procedure Initialize (Ctx : out Context);

   procedure Update (Ctx : in out Context; Input : String);
   procedure Update (Ctx : in out Context; Input : Element_Array);

   function Finalize (Ctx : in out Context) return Digest;
   procedure Finalize (Ctx : in out Context; Output : out Digest);

   function Hash (Input : String) return Digest;
   function Hash (Input : Element_Array) return Digest;
private
   use Interfaces;

   subtype Block is Element_Array (0 .. Block_Length - 1);

   type State_Array is array (Natural range 0 .. 4) of Unsigned_32;

   type Context is record
      State : State_Array :=
        (16#6745_2301#, 16#EFCD_AB89#, 16#98BA_DCFE#, 16#1032_5476#,
         16#C3D2_E1F0#);

      Count        : Index := 0;
      Buffer       : Block;
      Buffer_Index : Index := 0;
   end record;

   procedure Transform (Ctx : in out Context);
   function Ch (X, Y, Z : Unsigned_32) return Unsigned_32;
   function Parity (X, Y, Z : Unsigned_32) return Unsigned_32;
   function Maj (X, Y, Z : Unsigned_32) return Unsigned_32;

   generic
      type Input_Type is (<>);
   function To_Big_Endian (Input : Input_Type) return Element_Array;
end SHA1_Generic;
