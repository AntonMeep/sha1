with Interfaces;

generic
   type Element is mod <>;
   type Index is range <>;
   type Element_Array is array (Index range <>) of Element;
package SHA1_Generic with
   Pure,
   Preelaborate
is
   pragma Compile_Time_Error
     (Element'Modulus /= 256,
      "'Element' type must be mod 2**8, i.e. represent a byte");

   Digest_Length : constant Index := 20;
   Block_Length  : constant Index := 64;

   subtype Digest is
     Element_Array (Index'First .. Index'First + Digest_Length - 1);

   type Context is private;

   function Initialize return Context;
   procedure Initialize (Ctx : out Context);

   procedure Update (Ctx : in out Context; Input : String);
   procedure Update (Ctx : in out Context; Input : Element_Array);

   function Finalize (Ctx : Context) return Digest;
   procedure Finalize (Ctx : Context; Output : out Digest);

   function Hash (Input : String) return Digest;
   function Hash (Input : Element_Array) return Digest;
private
   use Interfaces;

   subtype Block is
     Element_Array (Index'First .. Index'First + Block_Length - 1);

   type Context is record
      H0 : Unsigned_32 := 16#6745_2301#;
      H1 : Unsigned_32 := 16#EFCD_AB89#;
      H2 : Unsigned_32 := 16#98BA_DCFE#;
      H3 : Unsigned_32 := 16#1032_5476#;
      H4 : Unsigned_32 := 16#C3D2_E1F0#;

      Count : Unsigned_64 := 0;

      Buffer : Block;
   end record;

   procedure Transform (Ctx : in out Context; Buffer : Block);
   function Ch (X, Y, Z : Unsigned_32) return Unsigned_32;
   function Parity (X, Y, Z : Unsigned_32) return Unsigned_32;
   function Maj (X, Y, Z : Unsigned_32) return Unsigned_32;
end SHA1_Generic;
