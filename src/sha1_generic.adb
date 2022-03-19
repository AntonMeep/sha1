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

   function Hash (Input : Element_Array) return Digest is
      Ctx : Context := Initialize;
   begin
      Update (Ctx, Input);
      return Finalize (Ctx);
   end Hash;
end SHA1_Generic;
