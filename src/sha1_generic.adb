pragma Ada_2012;
package body SHA1_Generic is
   function Initialize return Context is (others => <>);

   procedure Initialize (Ctx : out Context) is
   begin
      Ctx := (others => <>);
   end Initialize;

   procedure Update (Ctx : in out Context; Input : String) is
   begin
      pragma Compile_Time_Warning (Standard.True, "Update unimplemented");
      raise Program_Error with "Unimplemented procedure Update";
   end Update;

   procedure Update (Ctx : in out Context; Input : Element_Array) is
      First : Index := Input'First;
   begin
      Ctx.Count := Ctx.Count + Unsigned_64 (Input'Length);

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

   function Hash (Input : Element_Array) return Digest is
      Ctx : Context := Initialize;
   begin
      Update (Ctx, Input);
      return Finalize (Ctx);
   end Hash;

   procedure Transform (Ctx : in out Context; Buffer : Block) is
      type Words is array (Natural range <>) of Unsigned_32;

      Buffer_Words : Words (0 .. 15);
      for Buffer_Words'Address use Buffer'Address;

      W : Words (0 .. 79);

      A         : Unsigned_32 := Ctx.H0;
      B         : Unsigned_32 := Ctx.H1;
      C         : Unsigned_32 := Ctx.H2;
      D         : Unsigned_32 := Ctx.H3;
      E         : Unsigned_32 := Ctx.H4;
      Temporary : Unsigned_32;
   begin
      --  Byte order fix here

      W (0 .. 15) := Buffer_Words;

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
end SHA1_Generic;