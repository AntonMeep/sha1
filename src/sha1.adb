pragma Ada_2012;

package body SHA1 is
   function Initialize return Context is
      Ctx : Context;
   begin
      return Ctx;
   end Initialize;

   procedure Initialize (Ctx : out Context) is
      Result : Context;
   begin
      Ctx := Result;
   end Initialize;

   procedure Update (Ctx : in out Context; Input : String) is
      Buffer : Stream_Element_Array
        (Stream_Element_Offset (Input'First) ..
             Stream_Element_Offset (Input'Last));
      for Buffer'Address use Input'Address;
   begin
      Update (Ctx, Buffer);
   end Update;

   procedure Update (Ctx : in out Context; Input : Stream_Element_Array) is
   begin
      pragma Compile_Time_Warning (Standard.True, "Update unimplemented");
      raise Program_Error with "Unimplemented procedure Update";
   end Update;

   function Finalize (Ctx : Context) return Digest is
   begin
      pragma Compile_Time_Warning (Standard.True, "Finalize unimplemented");
      return raise Program_Error with "Unimplemented function Finalize";
   end Finalize;

   procedure Finalize (Ctx : Context; Output : out Digest) is
   begin
      pragma Compile_Time_Warning (Standard.True, "Finalize unimplemented");
      raise Program_Error with "Unimplemented procedure Finalize";
   end Finalize;

   function Hash (Input : String) return Digest is
      Ctx : Context := Initialize;
   begin
      Update (Ctx, Input);
      return Finalize (Ctx);
   end Hash;

   function Hash (Input : Stream_Element_Array) return Digest is
      Ctx : Context := Initialize;
   begin
      Update (Ctx, Input);
      return Finalize (Ctx);
   end Hash;

   procedure Transform (Ctx : in out Context; Buffer : Block) is
      type Words is array (Natural range <>) of Unsigned_32;

      W : Words (0 .. 79);

      A         : Unsigned_32 := Ctx.H0;
      B         : Unsigned_32 := Ctx.H1;
      C         : Unsigned_32 := Ctx.H2;
      D         : Unsigned_32 := Ctx.H3;
      E         : Unsigned_32 := Ctx.H4;
      Temporary : Unsigned_32;
   begin
      declare
         J : Stream_Element_Offset := Buffer'First;
      begin
         for I in 0 .. 15 loop
            W (I) :=
              Shift_Left (Unsigned_32 (Buffer (J + 0)), 24) or
              Shift_Left (Unsigned_32 (Buffer (J + 1)), 16) or
              Shift_Left (Unsigned_32 (Buffer (J + 2)), 8) or
              Unsigned_32 (Buffer (J + 3));
            J := J + 4;
         end loop;
      end;

      for I in 16 .. 79 loop
         W (I) :=
           Rotate_Left
             ((W (I - 3) xor W (I - 8) xor W (I - 14) xor W (I - 16)), 1);
      end loop;

      for I in 0 .. 19 loop
         Temporary :=
           Rotate_Left (A, 5) + Ch (B, C, D) + E + 16#5A82_7999# + W (I);
         E := D;
         D := C;
         C := Rotate_Left (B, 30);
         B := A;
         A := Temporary;
      end loop;

      for I in 20 .. 39 loop
         Temporary :=
           Rotate_Left (A, 5) + Parity (B, C, D) + E + 16#6ED9_EBA1# + W (I);
         E := D;
         D := C;
         C := Rotate_Left (B, 30);
         B := A;
         A := Temporary;
      end loop;

      for I in 40 .. 59 loop
         Temporary :=
           Rotate_Left (A, 5) + Maj (B, C, D) + E + 16#8F1B_BCDC# + W (I);
         E := D;
         D := C;
         C := Rotate_Left (B, 30);
         B := A;
         A := Temporary;
      end loop;

      for I in 60 .. 79 loop
         Temporary :=
           Rotate_Left (A, 5) + Parity (B, C, D) + E + 16#CA62_C1D6# + W (I);
         E := D;
         D := C;
         C := Rotate_Left (B, 30);
         B := A;
         A := Temporary;
      end loop;

      Ctx.H0 := Ctx.H0 + A;
      Ctx.H1 := Ctx.H1 + B;
      Ctx.H2 := Ctx.H2 + C;
      Ctx.H3 := Ctx.H3 + D;
      Ctx.H4 := Ctx.H4 + E;
   end Transform;

   function Ch (X, Y, Z : Unsigned_32) return Unsigned_32 is
     ((X and Y) xor ((not X) and Z));
   function Parity (X, Y, Z : Unsigned_32) return Unsigned_32 is
     (X xor Y xor Z);
   function Maj (X, Y, Z : Unsigned_32) return Unsigned_32 is
     ((X and Y) xor (X and Z) xor (Y and Z));
end SHA1;
