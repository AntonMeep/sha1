pragma Ada_2012;

with Ada.Unchecked_Conversion;
with GNAT.Byte_Swapping;
with System;

package body SHA1_Generic is
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
      Buffer : Element_Array (Index (Input'First) .. Index (Input'Last));
      for Buffer'Address use Input'Address;
   begin
      Update (Ctx, Buffer);
   end Update;

   procedure Update (Ctx : in out Context; Input : Element_Array) is
      Current : Index := Input'First;
   begin
      while Current <= Input'Last loop
         declare
            Bytes_To_Copy : constant Index :=
              Index'Min (Input'Length - (Current - Input'First), Block_Length);
         begin
            Ctx.Buffer
              (Ctx.Buffer_Index .. Ctx.Buffer_Index + Bytes_To_Copy - 1) :=
              Input (Current .. Current + Bytes_To_Copy - 1);
            Current          := Current + Bytes_To_Copy;
            Ctx.Buffer_Index := Ctx.Buffer_Index + Bytes_To_Copy;
            Ctx.Count        := Ctx.Count + Bytes_To_Copy;

            if Ctx.Buffer'Last < Ctx.Buffer_Index then
               Transform (Ctx);
               Ctx.Buffer_Index := Ctx.Buffer'First;
            end if;
         end;
      end loop;
   end Update;

   function Finalize (Ctx : in out Context) return Digest is
      Result : Digest;
   begin
      Finalize (Ctx, Result);
      return Result;
   end Finalize;

   procedure Finalize (Ctx : in out Context; Output : out Digest) is
      Current     : Index          := Output'First;
      Final_Count : constant Index := Ctx.Count * 8;

      function Index_To_Big_Endian is new To_Big_Endian (Index);
      function Unsigned32_To_Big_Endian is new To_Big_Endian (Unsigned_32);
   begin
      --  Insert padding
      Update (Ctx, Element_Array'(0 => 16#80#));

      if Ctx.Buffer'Last - Ctx.Buffer_Index < 8 then
         Update
           (Ctx,
            Element_Array'(0 .. (Ctx.Buffer'Last - Ctx.Buffer_Index) => 0));
      end if;

      Update
        (Ctx,
         Element_Array'(0 .. (Ctx.Buffer'Last - Ctx.Buffer_Index - 8) => 0));

      if Index'Size < 64 then
         --  In case Index is not a 64-bit number
         Update (Ctx, Element_Array'(0 .. (8 - Index'Size / 8 - 1) => 0));
      end if;

      Update (Ctx, Index_To_Big_Endian (Final_Count));

      for H of Ctx.State loop
         Output (Current + 0 .. Current + 3) := Unsigned32_To_Big_Endian (H);
         Current                             := Current + 4;
      end loop;
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
         use GNAT.Byte_Swapping;
         use System;

         Buffer_Words : Words (0 .. 15);
         for Buffer_Words'Address use Ctx.Buffer'Address;
      begin
         W (0 .. 15) := Buffer_Words;

         if Default_Bit_Order /= High_Order_First then
            --  Take care of endianess
            for I in W'Range loop
               Swap4 (W (I)'Address);
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

   function To_Big_Endian (Input : Input_Type) return Element_Array is
      use GNAT.Byte_Swapping;
      use System;

      subtype Output_Type is Element_Array (0 .. (Input_Type'Size / 8) - 1);
      function Convert is new Ada.Unchecked_Conversion
        (Input_Type, Output_Type);

      Result : Output_Type := Convert (Input);
   begin
      if Default_Bit_Order /= High_Order_First then
         if Input_Type'Size = 32 then
            Swap4 (Result'Address);
         elsif Input_Type'Size = 64 then
            Swap8 (Result'Address);
         else
            raise Program_Error;
         end if;
      end if;
      return Result;
   end To_Big_Endian;
end SHA1_Generic;
