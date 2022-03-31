with Interfaces;
with Ada.Streams; use Ada.Streams;

package SHA1 with
   Pure,
   Preelaborate,
   SPARK_Mode => On
is
   --  @summary
   --  Secure Hash Algorithm 1 implementation in Ada
   --
   --  @description
   --  This package provides implementation of SHA1 algorithm.

   Digest_Length : constant Stream_Element_Offset := 20;
   --  Length (in bytes) of the hash result

   Block_Length : constant Stream_Element_Offset := 64;
   --  Block length (in bytes), not very useful for the end user

   subtype Digest is Stream_Element_Array (0 .. Digest_Length - 1);
   --  Type representing the result of a hash function

   type Context is private;
   --  Algorithm context, holds all of the necessary internal data. Always
   --  initialized with correct data, calling Initialize() functions is not
   --  required but is strongly advised.

   function Initialize return Context;
   --  Initialize a Context properly. By default Context is already holding
   --  all of the necessary initialization values, this function is provided
   --  mainly for compatibility with other implementations.
   --  @return An initialized context

   procedure Initialize (Ctx : out Context);
   --  Ditto, but as a procedure.

   procedure Update (Ctx : in out Context; Input : String);
   --  Update Ctx with data from Input

   procedure Update (Ctx : in out Context; Input : Stream_Element_Array);
   --  Update Ctx with data from Input

   function Finalize (Ctx : Context) return Digest;
   --  Compute hash value and return it.

   procedure Finalize (Ctx : Context; Output : out Digest);
   --  Ditto, but as a procedure.

   function Hash (Input : String) return Digest;
   --  Compute hash of Input and return it. Essentially is an equivalent of
   --  Initialize, Update(Input) and Finalize.

   function Hash (Input : Stream_Element_Array) return Digest;
   --  Compute hash of Input and return it. Essentially is an equivalent of
   --  Initialize, Update(Input) and Finalize
private
   use Interfaces;

   subtype Block is Stream_Element_Array (0 .. Block_Length - 1);

   type State_Array is array (Natural range 0 .. 4) of Unsigned_32;

   type Context is record
      State : State_Array :=
        (16#6745_2301#, 16#EFCD_AB89#, 16#98BA_DCFE#, 16#1032_5476#,
         16#C3D2_E1F0#);

      Count  : Stream_Element_Offset := 0;
      Buffer : Block;
   end record;

   procedure Transform (Ctx : in out Context);
   pragma Inline (Transform);

   function Fast_Rem
     (A, B : Stream_Element_Offset) return Stream_Element_Offset;
   pragma Inline (Fast_Rem);
end SHA1;
