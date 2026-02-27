/*
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 Copyright (c) 2022-2023 Cascoda Ltd
 Copyright (c) 2024-2025 KNX Association
-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
 Licensed under the Apache License, Version 2.0 (the "License");
 you may not use this file except in compliance with the License.
 You may obtain a copy of the License at

      http://www.apache.org/licenses/LICENSE-2.0

 Unless required by applicable law or agreed to in writing, software
 distributed under the License is distributed on an "AS IS" BASIS,
 WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 See the License for the specific language governing permissions and
 limitations under the License.

-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=
*/

//needs to be undefined so wx widgets will not use precompiled headers when compiling with msvc
#undef WX_PRECOMP

#include <wx/wxprec.h>
#include <wx/wx.h>
#include "wx/sizer.h"
#include "wx/timer.h"
#include <wx/mstream.h>
#include <wx/image.h>
#include "api/oc_knx_dev.h"
#include "oc_knx_client.h"
#include "port/dns-sd.h"
#include "apps/hems/knx_iot_virtual_ems.h"
#include "apps/hems/icons/cem_ico.h"
#include <wx/clipbrd.h>
#include <wx/display.h>
#include <algorithm>

class CustomDialog : public wxDialog
{
public:
  CustomDialog(const wxString&, const wxString&);

private:
  void OnClose(wxCommandEvent& event);
};

void CustomDialog::OnClose(wxCommandEvent& event) { this->Destroy(); }

CustomDialog::CustomDialog(const wxString& title, const wxString& text) :
    wxDialog(NULL, wxID_ANY, title, wxDefaultPosition, wxDefaultSize,
             wxDEFAULT_DIALOG_STYLE | wxRESIZE_BORDER | wxMAXIMIZE_BOX)
{
  wxBoxSizer* vbox = new wxBoxSizer(wxVERTICAL);

  wxTextCtrl* tc =
    new wxTextCtrl(this, wxID_ANY, text, wxDefaultPosition, wxDefaultSize, wxTE_MULTILINE | wxTE_READONLY | wxHSCROLL);

  vbox->Add(tc, 1, wxEXPAND | wxALL, 10);

  wxButton* closeButton = new wxButton(this, wxID_OK, "Close");
  closeButton->Bind(wxEVT_BUTTON, &CustomDialog::OnClose, this);
  vbox->Add(closeButton, 0, wxALIGN_CENTER | wxALL, 10);

  SetSizer(vbox);

  // ---- Compute content-based size ----
  wxClientDC dc(this);
  dc.SetFont(tc->GetFont());

  wxArrayString lines = wxSplit(text, '\n');
  int lineHeight = dc.GetCharHeight();
  int maxWidth = 0;
  for (auto& line : lines)
  {
    int w, h;
    dc.GetTextExtent(line, &w, &h);
    maxWidth = std::max(w, maxWidth);
  }

  // Estimated natural size
  int width = maxWidth + 75; // padding
  int height = (lines.size() * lineHeight) + 150; // +button space

  // ---- Cap to 80% of screen ----
  wxDisplay display(wxDisplay::GetFromWindow(this));
  wxRect screenRect = display.GetGeometry();

  int maxW = screenRect.GetWidth() * 0.8;
  int maxH = screenRect.GetHeight() * 0.8;

  width = std::min(width, maxW);
  height = std::min(height, maxH);

  // Apply and allow resizing
  SetSize(width, height);
  SetMinSize(wxSize(100, 100)); // reasonable min

  Centre();
  ShowModal();
}

class MyApp : public wxApp
{
public:
  virtual bool OnInit();
};

class MyFrame : public wxFrame
{
public:
  MyFrame();

private:
  void OnListAll(wxCommandEvent& event);
  void OnProgrammingMode(wxCommandEvent& event);
  void OnReset(wxCommandEvent& event);
  void OnClearTables(wxCommandEvent& event);
  void OnExit(wxCommandEvent& event);
  void OnAbout(wxCommandEvent& event);
  void OnTimer(wxTimerEvent& event);

  void ProcessModeUpdate(wxCommandEvent& event);
  void OnProcessInverterUpdate();
  void updateDeviceData();

  wxMenu* m_menuFile;
  wxTimer m_timer;

  wxButton* m_mode_button;

  wxTextCtrl* m_inverter_text;  // text control for pv
  wxTextCtrl* m_charger_text;   // text control for charger
};

#ifdef USE_CONSOLE
wxIMPLEMENT_APP_CONSOLE(MyApp);
#else
wxIMPLEMENT_APP(MyApp);
#endif

bool MyApp::OnInit()
{
  // call in c-code
  app_initialize_stack("knx_iot_virtual_cem");

  wxInitAllImageHandlers();

  auto frame = new MyFrame();

  frame->SetSize(350, 200);
  frame->Show(true);
  return true;
}

MyFrame::MyFrame() : wxFrame(nullptr, wxID_ANY, "CEM")
{   
  wxMemoryInputStream iconStream(cem_ico, cem_ico_len);
  wxImage img(iconStream, wxBITMAP_TYPE_ICO);
  wxBitmap bmp(img);
  wxIcon icon;
  icon.CopyFromBitmap(bmp);
  SetIcon(icon);

  m_menuFile = new wxMenu;
  m_menuFile->Append(LIST_ALL, "List All Tables", "List all tables in one window", false);
  m_menuFile->AppendSeparator();
  m_menuFile->Append(CHECK_PM, "Programming Mode", "Sets the application in programming mode", true);
  m_menuFile->Append(RESET_TABLE, "Reset (7) (Tables)", "Reset 7 (Reset to default without IA)", false);
  m_menuFile->Append(RESET, "Reset (2) (ex-factory)", "Reset 2 (Reset to default state)", false);
  m_menuFile->AppendSeparator();
  m_menuFile->Append(wxID_EXIT);

  // help menu
  auto menuHelp = new wxMenu;
  menuHelp->Append(wxID_ABOUT, "About & Usage", "Show device information and usage instructions", false);

  // full menu bar
  auto menuBar = new wxMenuBar;
  menuBar->Append(m_menuFile, "&File");
  menuBar->Append(menuHelp, "&Help");
  wxFrameBase::SetMenuBar(menuBar);
  wxFrameBase::CreateStatusBar();

  Bind(wxEVT_MENU, &MyFrame::OnListAll, this, LIST_ALL);
  Bind(wxEVT_MENU, &MyFrame::OnProgrammingMode, this, CHECK_PM);
  Bind(wxEVT_MENU, &MyFrame::OnReset, this, RESET);
  Bind(wxEVT_MENU, &MyFrame::OnClearTables, this, RESET_TABLE);
  Bind(wxEVT_MENU, &MyFrame::OnAbout, this, wxID_ABOUT);
  Bind(wxEVT_MENU, &MyFrame::OnExit, this, wxID_EXIT);

  // cem section
  const auto v_box = new wxBoxSizer(wxVERTICAL);

  // row 1: mode button 
  m_mode_button = new wxButton(this, LS_TEXT, "sun mode", wxDefaultPosition, wxSize(100, 25));
  m_mode_button->Bind(wxEVT_BUTTON, &MyFrame::ProcessModeUpdate, this);

  const auto h_box1 = new wxBoxSizer(wxHORIZONTAL);
  h_box1->Add(m_mode_button, 0, wxEXPAND); // 0 = fixed width
  v_box->Add(h_box1, 0, wxEXPAND | wxALL, 10);

  // row 2: inverter text
  m_inverter_text = new wxTextCtrl(this, LS_TEXT, "... idle ...", wxDefaultPosition, wxSize(100, 25), wxBORDER_NONE);
  m_inverter_text->SetEditable(false);
  m_inverter_text->SetBackgroundColour(wxColour(127, 127, 127));

  const auto h_box2 = new wxBoxSizer(wxHORIZONTAL);
  h_box2->Add(m_inverter_text, 1, wxEXPAND); // stretches horizontally
  v_box->Add(h_box2, 0, wxEXPAND | wxALL, 10);

  // row 3: charger text 
  const auto h_box3 = new wxBoxSizer(wxHORIZONTAL);
  m_charger_text = new wxTextCtrl(this, LS_TEXT, "... idle ...", wxDefaultPosition, wxSize(100, 25), wxBORDER_NONE);
  m_charger_text->SetEditable(false);
  m_charger_text->SetBackgroundColour(wxColour(127, 127, 127));

  h_box3->Add(m_charger_text, 1, wxEXPAND); // stretches horizontally
  v_box->Add(h_box3, 0, wxEXPAND | wxALL, 10);

  this->SetSizerAndFit(v_box);

  // start the 1ms interval timer for UI updates and stack polls
  m_timer.Bind(wxEVT_TIMER, &MyFrame::OnTimer, this);
  m_timer.Start(1, wxTIMER_CONTINUOUS); 
}

void MyFrame::OnExit(wxCommandEvent& event) { Close(true); }

void MyFrame::OnProgrammingMode(wxCommandEvent& event)
{
  SetStatusText("Changing programming mode");

  bool my_val = m_menuFile->IsChecked(CHECK_PM);
  oc_device_info_t* device = oc_core_get_device_info();
  device->pm = my_val;

  // update the UI
  this->updateDeviceData();
  // update mdns
  knx_publish_service(oc_string(device->serialnumber), device->iid, device->ia, device->pm);
}

void MyFrame::updateDeviceData()
{
  oc_device_info_t* device = oc_core_get_device_info();

  // set in menu the programming mode to what the device has
  m_menuFile->Check(CHECK_PM, device->pm);
}

void MyFrame::OnClearTables(wxCommandEvent& event)
{
  SetStatusText("Clear Tables");
  // reset the device
  oc_knx_device_storage_reset(RESET_TO_DEFAULT_WO_IA);
  // update the UI
  this->updateDeviceData();
}

void MyFrame::OnReset(wxCommandEvent& event)
{
  SetStatusText("Device Reset");
  // reset the device
  oc_knx_device_storage_reset(RESET_TO_DEFAULT_STATE);
  // update the UI
  this->updateDeviceData();
}

void MyFrame::ProcessModeUpdate(wxCommandEvent& event)
{

  char text[200];
  
  float current_inverter_power = get_cem_inverter_value();
  float current_charger_power;
  float grid;

  if (get_cem_mode() == sun_mode)
  { // sun mode, toggle to mix mode

    set_cem_mode(mix_mode);
    m_mode_button->SetLabel("mix mode");

    // in watt
    current_charger_power = 4000;
    grid = current_inverter_power >= CEM_INVERTER_TRESHOLD ? 0 : 4000 - current_inverter_power;
  }
  else
  { // mix mode, toggle to sun mode

    set_cem_mode(sun_mode);
    m_mode_button->SetLabel("sun mode");

    // in watt
    current_charger_power = current_inverter_power <= CEM_INVERTER_TRESHOLD ? 0 : 4000;
    grid = 0;
  }

  // play with colors
  uint8_t r = 127;
  uint8_t g = 127 + static_cast<uint8_t>(current_charger_power / 32);
  uint8_t b = 127 + static_cast<uint8_t>(grid / 32);
  const wxColour charger_color = {r, g, b};

  m_charger_text->SetBackgroundColour(charger_color);

  (void)sprintf(text, "inverter in: %.02f kW", current_inverter_power / 1000);
  m_inverter_text->SetValue(text);

  (void)sprintf(text, "charger out: %.02f kW (%.02f kW from grid)", current_charger_power / 1000, grid / 1000);
  m_charger_text->SetValue(text);

  const char* url = app_retrieve_href_from_cem_charger();
  set_cem_charger_value(current_charger_power);

  // send message
  oc_send_s_mode_mc_or_uc_message(OC_SENDER_MULTICAST_SCOPE, url, 'w');
}

void MyFrame::OnListAll(wxCommandEvent& event)
{
  const oc_device_info_t* const device = oc_core_get_device_info();
  if (!device)
  {
    return;
  }

  bool ga_conversion = true;
  bool grpid_conversion = true;
  bool iid_conversion = true;

  wxString all;
  all << util_dumpQRCode()     << "\n\n"
      << util_dumpDeviceIDs()  << "\n\n"
      << util_dumpLsmState()   << "\n\n"
      << util_dumpGroupObjectTable(ga_conversion) << "\n\n"
      << util_dumpPublisherTable(ga_conversion, grpid_conversion, iid_conversion)   << "\n\n"
      << util_dumpRecipientTable(ga_conversion, grpid_conversion, iid_conversion)   << "\n\n"
      << util_dumpParameterList()    << "\n\n"
      << util_dumpAuthTable(ga_conversion);

  wxString title;
  title.Printf("CEM - Device & Tables - %s", oc_string(device->serialnumber));

  CustomDialog(title, all);
  SetStatusText("List Device & All Tables");
}

void MyFrame::OnAbout(wxCommandEvent& event)
{
  wxString usage;
  usage << "- The CEM has two operation modes:" << "\n"
        << "  1) Sun Mode: Car charges only if solar production is at least 4 kW." << "\n"
        << "  2) Mix Mode: Car charges at 4 kW regardless of solar availability." << "\n"
        << "- The CEM calculates and sends the appropriate charging rate to the charger." << "\n"
        << "\n"
        << "(c) KNX Association, 2025";

  CustomDialog("About", usage);
}

void MyFrame::OnTimer(wxTimerEvent& event)
{
  // stack polling
  (void)oc_main_poll();

  // data polling
  this->OnProcessInverterUpdate();

  // update possible user events
  this->updateDeviceData();
}

void MyFrame::OnProcessInverterUpdate()
{
  if (cem_inverter_flags() & new_event)
  {
    // clear event
    clear_cem_inverter_flags(new_event);

    char text[200];

    float current_inverter_power = get_cem_inverter_value();
    float current_charger_power;
    float grid;

    if (get_cem_mode() == sun_mode)
    { // sun mode

      // in watt
      current_charger_power = current_inverter_power <= CEM_INVERTER_TRESHOLD ? 0 : 4000;
      grid = 0;
    }
    else
    { // mix mode

      // in watt
      current_charger_power = 4000;
      grid = current_inverter_power >= CEM_INVERTER_TRESHOLD ? 0 : 4000 - current_inverter_power;
    }

    // play with colors
    uint8_t r = 127;
    uint8_t g = 127 + static_cast<uint8_t>(current_charger_power / 32);
    uint8_t b = 127 + static_cast<uint8_t>(grid / 32);
    const wxColour charger_color = {r, g, b};

    m_charger_text->SetBackgroundColour(charger_color);

    (void)sprintf(text, "inverter in: %.02f kW", current_inverter_power / 1000);
    m_inverter_text->SetValue(text);

    (void)sprintf(text, "charger out: %.02f kW (%.02f kW from grid)", current_charger_power / 1000, grid / 1000);
    m_charger_text->SetValue(text);

    const char* url = app_retrieve_href_from_cem_charger();
    set_cem_charger_value(current_charger_power);

    //TODO: optimize by only sending on value change and not on every update
    // send message
    oc_send_s_mode_mc_or_uc_message(OC_SENDER_MULTICAST_SCOPE, url, 'w');
  }
}
