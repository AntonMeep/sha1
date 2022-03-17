with Ada.Streams; use Ada.Streams;
with Interfaces;

package SHA1 with
   Pure,
   Preelaborate
is
   Digest_Length : constant Stream_Element_Offset := 20;
   Block_Length  : constant Stream_Element_Offset := 64;

   type Context is private;

   type Hash_Stream_Type (Ctx : access Context) is
     new Root_Stream_Type with private;

   subtype Digest is Stream_Element_Array (0 .. Digest_Length - 1);

   function Init return Context;
   procedure Init (Ctx : out Context);

   procedure Update (Ctx : in out Context; Input : String);
   procedure Update (Ctx : in out Context; Input : Wide_String);
   procedure Update (Ctx : in out Context; Input : Stream_Element_Array);

   function Final (Ctx : Context) return Digest;
   procedure Final (Ctx : Context; Output : out Digest);
private
   use Interfaces;

   type Context is record
      H0 : Unsigned_32 := 16#6745_2301#;
      H1 : Unsigned_32 := 16#EFCD_AB89#;
      H2 : Unsigned_32 := 16#98BA_DCFE#;
      H3 : Unsigned_32 := 16#1032_5476#;
      H4 : Unsigned_32 := 16#C3D2_E1F0#;

      Buffer : Stream_Element_Array (0 .. Block_Length - 1);
   end record;

   type Hash_Stream_Type (Ctx : access Context) is new Root_Stream_Type with
   null record;

   procedure Read
     (Stream : in out Hash_Stream_Type; Item : out Stream_Element_Array;
      Last   :    out Stream_Element_Offset);

   procedure Write
     (Stream : in out Hash_Stream_Type; Item : in Stream_Element_Array);
end SHA1;
