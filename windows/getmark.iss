// ----------------------------------------------------------------------------
//
// Inno Setup Ver:	5.5.7(a)
// Script Version:	1.0.2
// date:			2015-12-30
// Author:			JMSinfo <dev@jmsinfo.co>
// Homepage:		http://pombo.jmsinfo.co
// License:			GNU Lesser General Public License (LGPL), version 3
//						http://www.gnu.org/licenses/lgpl.html
//
// Script Function:
//	Add a select list to choose the computer mark.
//
// Instructions:
//	Copy getmakr.iss to the same directory as your setup script
//
//	Add this statement to your [Code] section
//		#include "getmark.iss"
//
//  The global variables below will be set:
//		{code:GetTheMark}: Acer
//		{code:GetTheMarkLower}: acer
//
// Changelog:
//	1.0.1
//		remove useless instructions (use of ItemIndex)
//		disable Next buton only if no choice selected
//		adjust list height
//	1.0.2
//		replace Hight() by GetArrayLength()-1
//
// ----------------------------------------------------------------------------

var
	PageStealthMode: TWizardPage;
	ChosenMark : TListBox;
	Marks : Array of String;
	MarksLower : Array of String;
	TheMark : String;
	TheMarkLower : String;

procedure OnPageStealthModeClicked(Sender: TObject);
var
	list : TListBox;
	selected : Integer;
begin
	list := TListBox(Sender);
	selected := list.ItemIndex;
	TheMark := list.Items[selected];
	TheMarkLower := MarksLower[selected];
	WizardForm.NextButton.Enabled := True;
end;

procedure CreatePageStealthMode;
var
	i : Integer;
begin
	Marks := [
		'Acer',
		'Alienware',
		'ASRock',
		'ASUS',
		'Compaq',
		'Cybertek',
		'Dell',
		'eMachines',
		'Fujitsu',
		'Gateway',
		'Giada',
		'Hewlett-Packard (HP)',
		'Intel',
		'LDLC',
		'Lenovo',
		'Medion',
		'MSI',
		'Ordissimo',
		'Packard Bell',
		'Samsung',
		'Sedatech',
		'Shuttle',
		'Sony',
		'Toshiba',
		'ZOTAC'
	];
	MarksLower := [
		'acer',
		'alienware',
		'asrock',
		'asus',
		'compaq',
		'cybertek',
		'dell',
		'emachines',
		'fujitsu',
		'gateway',
		'giada',
		'hp',
		'intel',
		'ldlc',
		'lenovo',
		'medion',
		'msi',
		'ordissimo',
		'packard-bell',
		'samsung',
		'sedatech',
		'shuttle',
		'sony',
		'toshiba',
		'zotac'
	];

	PageStealthMode := CreateCustomPage(wpLicense, ExpandConstant('{cm:marque_title}'), ExpandConstant('{cm:marque_texte}'));
	ChosenMark := TListBox.Create(PageStealthMode);
	ChosenMark.Width := PageStealthMode.SurfaceWidth;
	ChosenMark.Height := PageStealthMode.SurfaceHeight - 10;
	ChosenMark.Parent := PageStealthMode.Surface;
	ChosenMark.OnClick := @OnPageStealthModeClicked;
	for i := 0 to GetArrayLength(Marks)-1 do begin
		ChosenMark.Items.Add(Marks[i]);
	end;
end;

procedure CurPageChanged(CurPageID: Integer);
begin
  if CurPageID = PageStealthMode.ID then
    if ChosenMark.ItemIndex = -1 then
		WizardForm.NextButton.Enabled := False;
end;

procedure InitializeWizard;
begin
	CreatePageStealthMode;
end;

// Update the summary details
function UpdateReadyMemo(Space, NewLine, MemoUserInfoInfo, MemoDirInfo, MemoTypeInfo, MemoComponentsInfo, MemoGroupInfo, MemoTasksInfo: String): String;
var
	s : String;
begin
	s := NewLine + MemoComponentsInfo + NewLine + NewLine;
	if MemoTasksInfo <> '' then begin
		s := s + MemoTasksInfo + NewLine + NewLine;
	end;
	s := s + ExpandConstant('{cm:marque_memo}') + NewLine;
	s := s + '      ' + TheMark + ' (' + TheMarkLower + ')' + NewLine;
	Result := s;
end;

function GetTheMark(Param: String): String;
begin
  Result := TheMark;
end;

function GetTheMarkLower(Param: String): String;
begin
  Result := TheMarkLower;
end;
