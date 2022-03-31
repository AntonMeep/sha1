pragma Ada_2012;

with Endianness.Interfaces;
with System;

package body SHA1 is
   function Initialize return Context is
     ((State => <>, Count => 0, Buffer => (others => <>)));

   procedure Initialize (Ctx : out Context) is
   begin
      Ctx := Initialize;
   end Initialize;

   procedure Update (Ctx : in out Context; Input : String) is
      Buffer : Stream_Element_Array
        (Stream_Element_Offset (Input'First) ..
             Stream_Element_Offset (Input'Last));
      for Buffer'Address use Input'Address;
      pragma Import (Ada, Buffer);
   begin
      Update (Ctx, Buffer);
   end Update;

   procedure Update (Ctx : in out Context; Input : Stream_Element_Array) is
      Current : Stream_Element_Offset := Input'First;
   begin
      while Current <= Input'Last loop
         declare
            Buffer_Index : constant Stream_Element_Offset :=
              Ctx.Count rem Block_Length;
            Bytes_To_Copy : constant Stream_Element_Offset :=
              Stream_Element_Offset'Min
                (Input'Length - (Current - Input'First), Block_Length);
         begin
            Ctx.Buffer (Buffer_Index .. Buffer_Index + Bytes_To_Copy - 1) :=
              Input (Current .. Current + Bytes_To_Copy - 1);
            Current   := Current + Bytes_To_Copy;
            Ctx.Count := Ctx.Count + Bytes_To_Copy;

            if Ctx.Buffer'Last < Buffer_Index + Bytes_To_Copy then
               Transform (Ctx);
            end if;
         end;
      end loop;
   end Update;

   function Finalize (Ctx : Context) return Digest is
      Result : Digest;
   begin
      Finalize (Ctx, Result);
      return Result;
   end Finalize;

   procedure Finalize (Ctx : Context; Output : out Digest) is
      use Endianness.Interfaces;

      Current     : Stream_Element_Offset          := Output'First;
      Final_Count : constant Stream_Element_Offset := Ctx.Count;

      Ctx_Copy : Context := Ctx;
   begin
      --  Insert padding
      Update (Ctx_Copy, Stream_Element_Array'(0 => 16#80#));

      if Ctx_Copy.Buffer'Last - (Ctx_Copy.Count rem Block_Length) < 8 then
         --  In case not enough space is left in the buffer we fill it up
         Update
           (Ctx_Copy,
            Stream_Element_Array'
              (0 ..
                   (Ctx_Copy.Buffer'Last -
                    (Ctx_Copy.Count rem Block_Length)) =>
                 0));
      end if;

      --  Fill rest of the data with zeroes
      Update
        (Ctx_Copy,
         Stream_Element_Array'
           (0 ..
                (Ctx_Copy.Buffer'Last - (Ctx_Copy.Count rem Block_Length) -
                 8) =>
              0));

      --  Shift_Left(X, 3) is equivalent to multiplyng by 8
      Update
        (Ctx_Copy,
         Native_To_Big_Endian (Shift_Left (Unsigned_64 (Final_Count), 3)));

      for H of Ctx_Copy.State loop
         Output (Current + 0 .. Current + 3) := Native_To_Big_Endian (H);
         Current                             := Current + 4;
      end loop;
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

   procedure Transform (Ctx : in out Context) is
      type Words is array (Natural range <>) of Unsigned_32;

      W : Words (0 .. 79);

      A         : Unsigned_32 := Ctx.State (0);
      B         : Unsigned_32 := Ctx.State (1);
      C         : Unsigned_32 := Ctx.State (2);
      D         : Unsigned_32 := Ctx.State (3);
      E         : Unsigned_32 := Ctx.State (4);
      Temporary : Unsigned_32;
   begin
      declare
         use Endianness.Interfaces;
         use System;

         Buffer_Words : Words (0 .. 15);
         for Buffer_Words'Address use Ctx.Buffer'Address;
         pragma Import (Ada, Buffer_Words);
      begin
         W (0 .. 15) := Buffer_Words;

         if Default_Bit_Order /= High_Order_First then
            for WW of W loop
               WW := Swap_Endian (WW);
            end loop;
         end if;
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

      Ctx.State (0) := Ctx.State (0) + A;
      Ctx.State (1) := Ctx.State (1) + B;
      Ctx.State (2) := Ctx.State (2) + C;
      Ctx.State (3) := Ctx.State (3) + D;
      Ctx.State (4) := Ctx.State (4) + E;
   end Transform;

   function Ch (X, Y, Z : Unsigned_32) return Unsigned_32 is
     ((X and Y) xor ((not X) and Z));
   function Parity (X, Y, Z : Unsigned_32) return Unsigned_32 is
     (X xor Y xor Z);
   function Maj (X, Y, Z : Unsigned_32) return Unsigned_32 is
     ((X and Y) xor (X and Z) xor (Y and Z));
end SHA1;
